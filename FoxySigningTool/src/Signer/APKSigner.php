<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\DER;
use FoxyCryptLib\Hash;
use FoxyCryptLib\PEM;
use FoxyCryptLib\RSA;
use FoxyCryptLib\X509Certificate;
use ZipArchive;

final class APKSigner {
    private const ZIP_EOCD = "PK\x05\x06";
    private const ZIP_CENTRAL_DIRECTORY = "PK\x01\x02";
    private const APK_SIGNING_BLOCK_MAGIC = 'APK Sig Block 42';
    private const APK_SIGNATURE_SCHEME_V2_ID = 0x7109871a;
    private const APK_SIGNATURE_SCHEME_V3_ID = 0xf05368c0;
    private const APK_SIGNING_BLOCK_PADDING_ID = 0x42726577;
    private const STRIPPING_PROTECTION_ATTRIBUTE_ID = 0xbeeff00d;
    private const RSA_PKCS1_SHA256_ID = 0x0103;
    private const APK_SIGNING_BLOCK_ALIGNMENT = 4096;
    private const CONTENT_DIGEST_CHUNK_SIZE = 1048576;

    private const DEFAULT_MAX_ZIP_ENTRIES = 20000;
    private const DEFAULT_MAX_ZIP_ENTRY_SIZE = 268435456;
    private const DEFAULT_MAX_ZIP_TOTAL_SIZE = 536870912;
    private const DEFAULT_MAX_ZIP_RATIO = 200;
    private const DEFAULT_MAX_APK_SIZE = 536870912;

    private RSA $signerKey;
    private RSA $verifierKey;
    private string $certificateDer;
    private string $issuerDer;
    private string $serialNumber;
    private string $publicKeyDer;
    private array $extraCertificatesDer = [];

    public function __construct(
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = []
    ) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('APK signing currently requires an RSA private key');
        }
        if (strtolower(str_replace('-', '', $hashAlgo)) !== 'sha256') {
            throw new \InvalidArgumentException('APK signing currently supports SHA-256 only');
        }
        if (($signerKey->getPrivateKey()['d'] ?? null) === null) {
            throw new \InvalidArgumentException('APK signing requires an RSA private key');
        }

        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(PEM::encode(
                $certificate['subjectPublicKeyInfo']['raw'],
                'PUBLIC KEY'
            ));
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('APK signing requires an RSA certificate', 0, $exception);
        }

        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('APK signing key does not match the certificate');
        }

        $this->signerKey = $signerKey;
        $this->verifierKey = $certificateKey;
        $this->certificateDer = PEM::decode($certPem)['data'];
        $this->issuerDer = $certificate['issuer']['raw'];
        $this->serialNumber = $certificate['serialNumber']->toBytes();
        $this->publicKeyDer = X509Certificate::encodeSPKI($certificateKey);

        foreach ($extraCerts as $extraCert) {
            if (!is_string($extraCert)) {
                throw new \InvalidArgumentException('Each extra certificate must be PEM encoded');
            }
            X509Certificate::fromPEM($extraCert);
            $der = PEM::decode($extraCert)['data'];
            if ($der !== $this->certificateDer && !in_array($der, $this->extraCertificatesDer, true)) {
                $this->extraCertificatesDer[] = $der;
            }
        }
    }

    public function signFile(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $config = $this->validateOptions($options);
        $outputPath ??= $inputPath;
        if (is_dir($outputPath)) {
            throw new \RuntimeException("APK output path is a directory: {$outputPath}");
        }
        $inputSize = @filesize($inputPath);
        if ($inputSize === false) {
            throw new \RuntimeException("Unable to inspect APK: {$inputPath}");
        }
        if ($inputSize > $config['maxApkSize']) {
            throw new \RuntimeException("APK exceeds the permitted file size: {$inputPath}");
        }
        $apk = @file_get_contents($inputPath);
        if ($apk === false) {
            throw new \RuntimeException("Unable to read APK: {$inputPath}");
        }

        $signed = $this->signBinary($apk, $options);
        $mode = @fileperms($inputPath);
        $this->writeFileSafely($outputPath, $signed, $mode === false ? null : ($mode & 0777));
        return $outputPath;
    }

    public function signBinary(string $apk, array $options = []): string {
        $config = $this->validateOptions($options);
        if (strlen($apk) > $config['maxApkSize']) {
            throw new \RuntimeException('APK exceeds the permitted file size');
        }
        $v1HashAlgo = $config['apkMinSdk'] < 18 ? 'sha1' : 'sha256';

        $apk = $this->stripExistingSigningBlock($apk);
        $apk = $this->addV1Signature($apk, $config, $v1HashAlgo);
        if (strlen($apk) > $config['maxApkSize']) {
            throw new \RuntimeException('v1-signed APK exceeds the permitted file size');
        }
        $apk = $this->stripExistingSigningBlock($apk);

        $zip = $this->parseZip($apk);
        $beforeCentralDirectory = substr($apk, 0, $zip['centralDirectoryOffset']);
        $preBlockPadding = (self::APK_SIGNING_BLOCK_ALIGNMENT
            - (strlen($beforeCentralDirectory) % self::APK_SIGNING_BLOCK_ALIGNMENT))
            % self::APK_SIGNING_BLOCK_ALIGNMENT;
        if ($preBlockPadding > 0) {
            $beforeCentralDirectory .= str_repeat("\x00", $preBlockPadding);
        }
        $signingBlockOffset = strlen($beforeCentralDirectory);
        $centralDirectory = substr(
            $apk,
            $zip['centralDirectoryOffset'],
            $zip['centralDirectorySize']
        );
        $eocd = substr($apk, $zip['eocdOffset']);
        $digestEocd = $this->replaceUInt32($eocd, 16, $signingBlockOffset);
        $contentDigest = $this->computeContentDigest([
            $beforeCentralDirectory,
            $centralDirectory,
            $digestEocd,
        ]);

        $pairs = [
            [self::APK_SIGNATURE_SCHEME_V2_ID, $this->buildV2BlockValue($contentDigest)],
            [self::APK_SIGNATURE_SCHEME_V3_ID, $this->buildV3BlockValue($contentDigest, 24, 0x7fffffff)],
        ];
        $signingBlock = $this->buildSigningBlock($pairs);
        $newCentralDirectoryOffset = $signingBlockOffset + strlen($signingBlock);
        if ($newCentralDirectoryOffset > 0xffffffff) {
            throw new \RuntimeException('Signed APK would require ZIP64, which is not supported');
        }
        $finalEocd = $this->replaceUInt32($eocd, 16, $newCentralDirectoryOffset);

        $signed = $beforeCentralDirectory . $signingBlock . $centralDirectory . $finalEocd;
        if (strlen($signed) > $config['maxApkSize']) {
            throw new \RuntimeException('Signed APK exceeds the permitted file size');
        }
        return $signed;
    }

    private function addV1Signature(string $apk, array $config, string $hashAlgo): string {
        $zipInfo = $this->parseZip($apk);
        $temporary = tempnam(sys_get_temp_dir(), 'foxy-apk-');
        if ($temporary === false) {
            throw new \RuntimeException('Unable to create a temporary APK');
        }
        if (@file_put_contents($temporary, $apk) !== strlen($apk)) {
            @unlink($temporary);
            throw new \RuntimeException('Unable to initialize a temporary APK');
        }

        $zip = new ZipArchive();
        $opened = false;
        try {
            $result = $zip->open($temporary, ZipArchive::CHECKCONS);
            if ($result !== true) {
                throw new \RuntimeException("Unable to open APK ZIP archive (ZipArchive error {$result})");
            }
            $opened = true;

            $maxEntries = $config['maxZipEntries'];
            $maxEntrySize = $config['maxZipEntrySize'];
            $maxTotalSize = $config['maxZipTotalSize'];
            $maxRatio = $config['maxZipCompressionRatio'];
            if ($zip->numFiles > $maxEntries) {
                throw new \RuntimeException("APK has too many ZIP entries ({$zip->numFiles})");
            }
            $rawRecords = $this->centralDirectoryRecords($apk, $zipInfo);
            if (count($rawRecords) !== $zip->numFiles) {
                throw new \RuntimeException('APK ZIP entry count changed while opening the archive');
            }

            $entryDigests = [];
            $seen = [];
            $totalSize = 0;
            $sourceManifest = null;
            $hasAndroidManifest = false;

            for ($index = 0; $index < $zip->numFiles; $index++) {
                $stat = $zip->statIndex($index);
                if ($stat === false || !isset($stat['name'], $stat['size'], $stat['comp_size'])) {
                    throw new \RuntimeException("Unable to inspect APK ZIP entry {$index}");
                }
                $name = $rawRecords[$index]['name'];
                $this->validateEntryName($name);
                $seenKey = "\x00" . $name;
                if (isset($seen[$seenKey])) {
                    throw new \RuntimeException("Duplicate APK ZIP entry: {$name}");
                }
                $seen[$seenKey] = true;

                $size = (int)$stat['size'];
                $compressedSize = (int)$stat['comp_size'];
                if ($size < 0 || $compressedSize < 0 || $size > $maxEntrySize) {
                    throw new \RuntimeException("APK ZIP entry exceeds the permitted size: {$name}");
                }
                if ($totalSize > $maxTotalSize - $size) {
                    throw new \RuntimeException('APK exceeds the permitted uncompressed size');
                }
                $totalSize += $size;

                $method = (int)($stat['comp_method'] ?? ZipArchive::CM_STORE);
                if (!in_array($method, [ZipArchive::CM_STORE, ZipArchive::CM_DEFLATE], true)) {
                    throw new \RuntimeException("Unsupported APK ZIP compression method for: {$name}");
                }
                $encryption = (int)($stat['encryption_method'] ?? ZipArchive::EM_NONE);
                if ($encryption !== ZipArchive::EM_NONE) {
                    throw new \RuntimeException("Encrypted APK ZIP entries are not supported: {$name}");
                }
                if ($size > 0
                    && ($compressedSize === 0 || ($size / $compressedSize) > $maxRatio)) {
                    throw new \RuntimeException("APK ZIP entry has an unsafe compression ratio: {$name}");
                }

                if ($name === 'AndroidManifest.xml') {
                    $hasAndroidManifest = true;
                }
                if ($this->isRemovedEntry($name)) {
                    if (strcasecmp($name, 'META-INF/MANIFEST.MF') === 0) {
                        $contents = $zip->getFromIndex($index);
                        if ($contents === false) {
                            throw new \RuntimeException('Unable to read existing APK manifest');
                        }
                        $sourceManifest = $contents;
                    }
                    continue;
                }
                if (!$this->isV1DigestEntry($name)) {
                    continue;
                }

                $contents = $zip->getFromIndex($index);
                if ($contents === false || strlen($contents) !== $size) {
                    throw new \RuntimeException("Unable to read complete APK ZIP entry: {$name}");
                }
                $entryDigests[] = ['name' => $name, 'digest' => $this->rawHash($contents, $hashAlgo)];
            }

            if (!$hasAndroidManifest) {
                throw new \RuntimeException('APK is missing AndroidManifest.xml');
            }

            [$manifest, $manifestSections] = $this->buildManifest(
                $entryDigests,
                $sourceManifest,
                $hashAlgo
            );
            $createdBy = $config['apkCreatedBy'];
            $signatureFile = $this->buildSignatureFile(
                $manifest,
                $manifestSections,
                $createdBy,
                $hashAlgo
            );
            $signatureBlock = $this->buildV1SignatureBlock($signatureFile, $hashAlgo);
            $signerName = $config['apkSignerName'];
            $generatedSize = strlen($manifest) + strlen($signatureFile) + strlen($signatureBlock);
            if (strlen($manifest) > $maxEntrySize
                || strlen($signatureFile) > $maxEntrySize
                || strlen($signatureBlock) > $maxEntrySize
                || $totalSize > $maxTotalSize - $generatedSize) {
                throw new \RuntimeException('Generated APK v1 signature entries exceed the ZIP size limits');
            }
            $updates = [
                ['name' => 'META-INF/MANIFEST.MF', 'contents' => $manifest],
                ['name' => "META-INF/{$signerName}.SF", 'contents' => $signatureFile],
                ['name' => "META-INF/{$signerName}.RSA", 'contents' => $signatureBlock],
            ];

            $opened = false;
            if (!$zip->close()) {
                throw new \RuntimeException('Unable to close APK ZIP archive');
            }
            return $this->rebuildZipWithV1Entries($apk, $zipInfo, $updates);
        } finally {
            if ($opened) {
                try {
                    $zip->close();
                } catch (\Throwable) {
                    // Preserve the original failure while still removing the temporary APK.
                }
            }
            @unlink($temporary);
        }
    }

    private function rebuildZipWithV1Entries(string $apk, array $zip, array $updates): string {
        $records = $this->centralDirectoryRecords($apk, $zip);
        $centralDirectory = '';
        $retainedEntries = 0;
        foreach ($records as $record) {
            if ($this->isRemovedEntry($record['name'])) {
                continue;
            }
            $centralDirectory .= $record['raw'];
            $retainedEntries++;
        }

        $localDataEnd = $this->trailingRemovedEntriesOffset(
            $apk,
            $records,
            $zip['centralDirectoryOffset']
        );
        $beforeCentralDirectory = substr($apk, 0, $localDataEnd);
        foreach ($updates as $update) {
            [$localRecord, $centralRecord] = $this->buildStoredZipEntry(
                $update['name'],
                $update['contents'],
                strlen($beforeCentralDirectory)
            );
            $beforeCentralDirectory .= $localRecord;
            $centralDirectory .= $centralRecord;
        }

        $entryCount = $retainedEntries + count($updates);
        if ($entryCount > 0xfffe
            || strlen($beforeCentralDirectory) > 0xffffffff
            || strlen($centralDirectory) > 0xffffffff) {
            throw new \RuntimeException('v1-signed APK would require ZIP64, which is not supported');
        }
        $eocd = substr($apk, $zip['eocdOffset']);
        $eocd = $this->replaceUInt16($eocd, 8, $entryCount);
        $eocd = $this->replaceUInt16($eocd, 10, $entryCount);
        $eocd = $this->replaceUInt32($eocd, 12, strlen($centralDirectory));
        $eocd = $this->replaceUInt32($eocd, 16, strlen($beforeCentralDirectory));

        return $beforeCentralDirectory . $centralDirectory . $eocd;
    }

    private function centralDirectoryRecords(string $apk, array $zip): array {
        $records = [];
        $offset = $zip['centralDirectoryOffset'];
        $end = $offset + $zip['centralDirectorySize'];
        for ($index = 0; $index < $zip['entryCount']; $index++) {
            if ($offset + 46 > $end
                || substr($apk, $offset, 4) !== self::ZIP_CENTRAL_DIRECTORY) {
                throw new \RuntimeException("Malformed APK Central Directory record {$index}");
            }
            $nameLength = $this->readUInt16($apk, $offset + 28);
            $extraLength = $this->readUInt16($apk, $offset + 30);
            $commentLength = $this->readUInt16($apk, $offset + 32);
            $recordLength = 46 + $nameLength + $extraLength + $commentLength;
            if ($offset + $recordLength > $end) {
                throw new \RuntimeException("Truncated APK Central Directory record {$index}");
            }
            $name = substr($apk, $offset + 46, $nameLength);
            $this->validateEntryName($name);
            $compressedSize = $this->readUInt32($apk, $offset + 20);
            $uncompressedSize = $this->readUInt32($apk, $offset + 24);
            $diskNumber = $this->readUInt16($apk, $offset + 34);
            $localOffset = $this->readUInt32($apk, $offset + 42);
            $extra = substr($apk, $offset + 46 + $nameLength, $extraLength);
            if ($compressedSize === 0xffffffff
                || $uncompressedSize === 0xffffffff
                || $localOffset === 0xffffffff
                || $diskNumber !== 0
                || $this->containsZip64Extra($extra)) {
                throw new \RuntimeException('ZIP64 APK entries are not supported');
            }
            $this->validateLocalZipRecord($apk, $localOffset, $name);
            $records[] = [
                'name' => $name,
                'localOffset' => $localOffset,
                'raw' => substr($apk, $offset, $recordLength),
            ];
            $offset += $recordLength;
        }
        if ($offset !== $end) {
            throw new \RuntimeException('APK Central Directory contains unsupported trailing records');
        }
        return $records;
    }

    private function trailingRemovedEntriesOffset(
        string $apk,
        array $records,
        int $centralDirectoryOffset
    ): int {
        usort(
            $records,
            static fn(array $left, array $right): int => $left['localOffset'] <=> $right['localOffset']
        );
        $truncateOffset = $centralDirectoryOffset;
        $found = false;
        for ($index = count($records) - 1; $index >= 0; $index--) {
            if (!$this->isRemovedEntry($records[$index]['name'])) {
                break;
            }
            $truncateOffset = $records[$index]['localOffset'];
            $found = true;
        }
        if (!$found || substr($apk, $truncateOffset, 4) !== "PK\x03\x04") {
            return $centralDirectoryOffset;
        }
        return $truncateOffset;
    }

    private function validateLocalZipRecord(string $apk, int $offset, string $centralName): void {
        if ($offset < 0
            || $offset + 30 > strlen($apk)
            || substr($apk, $offset, 4) !== "PK\x03\x04") {
            throw new \RuntimeException("Invalid APK local ZIP record for: {$centralName}");
        }
        $compressedSize = $this->readUInt32($apk, $offset + 18);
        $uncompressedSize = $this->readUInt32($apk, $offset + 22);
        $nameLength = $this->readUInt16($apk, $offset + 26);
        $extraLength = $this->readUInt16($apk, $offset + 28);
        if ($offset + 30 + $nameLength + $extraLength > strlen($apk)) {
            throw new \RuntimeException("Truncated APK local ZIP record for: {$centralName}");
        }
        $localName = substr($apk, $offset + 30, $nameLength);
        $extra = substr($apk, $offset + 30 + $nameLength, $extraLength);
        if ($localName !== $centralName
            || $compressedSize === 0xffffffff
            || $uncompressedSize === 0xffffffff
            || $this->containsZip64Extra($extra)) {
            throw new \RuntimeException("ZIP64 or mismatched APK local record for: {$centralName}");
        }
    }

    private function containsZip64Extra(string $extra): bool {
        for ($offset = 0, $length = strlen($extra); $offset < $length;) {
            $remaining = substr($extra, $offset);
            if (trim($remaining, "\x00") === '') {
                return false;
            }
            if ($offset + 4 > $length) {
                throw new \RuntimeException('Malformed APK ZIP extra field');
            }
            $id = $this->readUInt16($extra, $offset);
            $dataLength = $this->readUInt16($extra, $offset + 2);
            $offset += 4;
            if ($offset + $dataLength > $length) {
                throw new \RuntimeException('Truncated APK ZIP extra field');
            }
            if ($id === 0x0001) {
                return true;
            }
            $offset += $dataLength;
        }
        return false;
    }

    private function buildStoredZipEntry(string $name, string $contents, int $localOffset): array {
        $nameLength = strlen($name);
        $size = strlen($contents);
        if ($nameLength > 0xffff || $size > 0xffffffff || $localOffset > 0xffffffff) {
            throw new \RuntimeException("APK signature ZIP entry is too large: {$name}");
        }
        $crc = crc32($contents);
        if ($crc < 0) {
            $crc += 0x100000000;
        }
        $year = max(1980, min(2107, (int)date('Y')));
        $dosDate = (($year - 1980) << 9) | ((int)date('n') << 5) | (int)date('j');
        $dosTime = ((int)date('G') << 11) | ((int)date('i') << 5) | intdiv((int)date('s'), 2);
        $flags = 0x0800;
        $local = pack(
            'VvvvvvVVVvv',
            0x04034b50,
            20,
            $flags,
            ZipArchive::CM_STORE,
            $dosTime,
            $dosDate,
            $crc,
            $size,
            $size,
            $nameLength,
            0
        ) . $name . $contents;
        $central = pack(
            'VvvvvvvVVVvvvvvVV',
            0x02014b50,
            0x0314,
            20,
            $flags,
            ZipArchive::CM_STORE,
            $dosTime,
            $dosDate,
            $crc,
            $size,
            $size,
            $nameLength,
            0,
            0,
            0,
            0,
            0,
            $localOffset
        ) . $name;
        return [$local, $central];
    }

    private function buildManifest(
        array $entryDigests,
        ?string $sourceManifest,
        string $hashAlgo
    ): array {
        $attributes = $sourceManifest === null
            ? [['name' => 'Manifest-Version', 'value' => '1.0']]
            : $this->parseManifestMainAttributes($sourceManifest);

        $manifestVersion = null;
        $remainingAttributes = [];
        foreach ($attributes as $attribute) {
            if (strcasecmp($attribute['name'], 'Manifest-Version') === 0) {
                $manifestVersion = $attribute['value'];
            } else {
                $remainingAttributes[] = $attribute;
            }
        }
        if ($manifestVersion === null) {
            throw new \RuntimeException('Existing APK manifest has no Manifest-Version attribute');
        }

        $manifest = $this->jarHeader('Manifest-Version', $manifestVersion);
        usort(
            $remainingAttributes,
            static fn(array $left, array $right): int => strcmp($left['name'], $right['name'])
        );
        foreach ($remainingAttributes as $attribute) {
            $manifest .= $this->jarHeader($attribute['name'], $attribute['value']);
        }
        $manifest .= "\r\n";

        usort(
            $entryDigests,
            static fn(array $left, array $right): int => strcmp($left['name'], $right['name'])
        );
        $digestAttribute = $hashAlgo === 'sha1' ? 'SHA1-Digest' : 'SHA-256-Digest';
        $sections = [];
        foreach ($entryDigests as $entry) {
            $section = $this->jarHeader('Name', $entry['name'])
                . $this->jarHeader($digestAttribute, base64_encode($entry['digest']))
                . "\r\n";
            $sections[] = ['name' => $entry['name'], 'contents' => $section];
            $manifest .= $section;
        }
        return [$manifest, $sections];
    }

    private function buildSignatureFile(
        string $manifest,
        array $manifestSections,
        string $createdBy,
        string $hashAlgo
    ): string {
        $digestAttribute = $hashAlgo === 'sha1' ? 'SHA1-Digest' : 'SHA-256-Digest';
        $manifestDigestAttribute = $digestAttribute . '-Manifest';
        $attributes = [
            ['name' => 'Created-By', 'value' => $createdBy],
            [
                'name' => $manifestDigestAttribute,
                'value' => base64_encode($this->rawHash($manifest, $hashAlgo)),
            ],
            ['name' => 'X-Android-APK-Signed', 'value' => '2, 3'],
        ];
        usort(
            $attributes,
            static fn(array $left, array $right): int => strcmp($left['name'], $right['name'])
        );

        $signatureFile = $this->jarHeader('Signature-Version', '1.0');
        foreach ($attributes as $attribute) {
            $signatureFile .= $this->jarHeader($attribute['name'], $attribute['value']);
        }
        $signatureFile .= "\r\n";

        foreach ($manifestSections as $section) {
            $signatureFile .= $this->jarHeader('Name', $section['name'])
                . $this->jarHeader(
                    $digestAttribute,
                    base64_encode($this->rawHash($section['contents'], $hashAlgo))
                )
                . "\r\n";
        }
        if ($signatureFile !== '' && strlen($signatureFile) % 1024 === 0) {
            $signatureFile .= "\r\n";
        }
        return $signatureFile;
    }

    private function buildV1SignatureBlock(string $signatureFile, string $hashAlgo): string {
        $digestOid = $hashAlgo === 'sha1'
            ? '1.3.14.3.2.26'
            : '2.16.840.1.101.3.4.2.1';
        $digestAlgorithm = DER::encodeSequence([
            DER::encodeOID($digestOid),
            DER::encodeNull(),
        ]);
        $signatureAlgorithm = DER::encodeSequence([
            DER::encodeOID('1.2.840.113549.1.1.1'),
            DER::encodeNull(),
        ]);
        $signature = $this->signRawData($signatureFile, $hashAlgo);
        $issuerAndSerial = DER::encodeSequence([
            $this->issuerDer,
            DER::encodeInteger($this->serialNumber),
        ]);
        $signerInfo = DER::encodeSequence([
            DER::encodeInteger("\x01"),
            $issuerAndSerial,
            $digestAlgorithm,
            $signatureAlgorithm,
            DER::encodeOctetString($signature),
        ]);

        $certificates = array_merge([$this->certificateDer], $this->extraCertificatesDer);
        usort($certificates, static fn(string $left, string $right): int => strcmp($left, $right));
        $signedData = DER::encodeSequence([
            DER::encodeInteger("\x01"),
            DER::encodeSet([$digestAlgorithm]),
            DER::encodeSequence([DER::encodeOID('1.2.840.113549.1.7.1')]),
            DER::encodeContextSpecific(0, implode('', $certificates), true),
            DER::encodeSet([$signerInfo]),
        ]);

        return DER::encodeSequence([
            DER::encodeOID('1.2.840.113549.1.7.2'),
            DER::encodeContextSpecific(0, $signedData, true),
        ]);
    }

    private function buildV2BlockValue(string $contentDigest): string {
        $digestRecords = $this->algorithmRecord(self::RSA_PKCS1_SHA256_ID, $contentDigest);
        $attributes = $this->attributeRecord(
            self::STRIPPING_PROTECTION_ATTRIBUTE_ID,
            $this->uint32(3)
        );
        $signedData = $this->lengthPrefixed($digestRecords)
            . $this->lengthPrefixed($this->certificateSequence())
            . $this->lengthPrefixed($attributes)
            . $this->lengthPrefixed('');
        $signatures = $this->algorithmRecord(
            self::RSA_PKCS1_SHA256_ID,
            $this->signRawData($signedData)
        );
        $signer = $this->lengthPrefixed($signedData)
            . $this->lengthPrefixed($signatures)
            . $this->lengthPrefixed($this->publicKeyDer);

        return $this->lengthPrefixed($this->lengthPrefixed($signer));
    }

    private function buildV3BlockValue(string $contentDigest, int $minSdk, int $maxSdk): string {
        $digestRecords = $this->algorithmRecord(self::RSA_PKCS1_SHA256_ID, $contentDigest);
        $signedData = $this->lengthPrefixed($digestRecords)
            . $this->lengthPrefixed($this->certificateSequence())
            . $this->uint32($minSdk)
            . $this->uint32($maxSdk)
            . $this->lengthPrefixed('');
        $signatures = $this->algorithmRecord(
            self::RSA_PKCS1_SHA256_ID,
            $this->signRawData($signedData)
        );
        $signer = $this->lengthPrefixed($signedData)
            . $this->uint32($minSdk)
            . $this->uint32($maxSdk)
            . $this->lengthPrefixed($signatures)
            . $this->lengthPrefixed($this->publicKeyDer);

        return $this->lengthPrefixed($this->lengthPrefixed($signer));
    }

    private function certificateSequence(): string {
        $certificates = $this->lengthPrefixed($this->certificateDer);
        foreach ($this->extraCertificatesDer as $certificate) {
            $certificates .= $this->lengthPrefixed($certificate);
        }
        return $certificates;
    }

    private function computeContentDigest(array $sections): string {
        $chunkCount = 0;
        foreach ($sections as $section) {
            $chunkCount += intdiv(strlen($section) + self::CONTENT_DIGEST_CHUNK_SIZE - 1, self::CONTENT_DIGEST_CHUNK_SIZE);
        }
        if ($chunkCount > 0x7fffffff) {
            throw new \RuntimeException('APK contains too many content-digest chunks');
        }

        $finalInput = "\x5a" . $this->uint32($chunkCount);
        foreach ($sections as $section) {
            $length = strlen($section);
            for ($offset = 0; $offset < $length; $offset += self::CONTENT_DIGEST_CHUNK_SIZE) {
                $chunk = substr($section, $offset, self::CONTENT_DIGEST_CHUNK_SIZE);
                $finalInput .= $this->rawHash("\xa5" . $this->uint32(strlen($chunk)) . $chunk);
            }
        }
        return $this->rawHash($finalInput);
    }

    private function buildSigningBlock(array $pairs): string {
        $encodedPairs = '';
        foreach ($pairs as [$id, $value]) {
            $pairLength = 4 + strlen($value);
            if ($pairLength > 0x7fffffff) {
                throw new \RuntimeException('APK signing pair is too large');
            }
            $encodedPairs .= $this->uint64($pairLength) . $this->uint32($id) . $value;
        }

        $blockLength = 32 + strlen($encodedPairs);
        $paddingLength = (self::APK_SIGNING_BLOCK_ALIGNMENT
            - ($blockLength % self::APK_SIGNING_BLOCK_ALIGNMENT))
            % self::APK_SIGNING_BLOCK_ALIGNMENT;
        if ($paddingLength > 0 && $paddingLength < 12) {
            $paddingLength += self::APK_SIGNING_BLOCK_ALIGNMENT;
        }
        if ($paddingLength > 0) {
            $encodedPairs .= $this->uint64($paddingLength - 8)
                . $this->uint32(self::APK_SIGNING_BLOCK_PADDING_ID)
                . str_repeat("\x00", $paddingLength - 12);
        }

        $size = strlen($encodedPairs) + 24;
        return $this->uint64($size)
            . $encodedPairs
            . $this->uint64($size)
            . self::APK_SIGNING_BLOCK_MAGIC;
    }

    private function stripExistingSigningBlock(string $apk): string {
        $zip = $this->parseZip($apk);
        $centralDirectoryOffset = $zip['centralDirectoryOffset'];
        if ($centralDirectoryOffset < 24
            || substr($apk, $centralDirectoryOffset - 16, 16) !== self::APK_SIGNING_BLOCK_MAGIC) {
            return $apk;
        }

        $footerSize = $this->readUInt64($apk, $centralDirectoryOffset - 24);
        if ($footerSize < 24) {
            throw new \RuntimeException('Existing APK Signing Block is too small');
        }
        $totalSize = $footerSize + 8;
        if ($totalSize > $centralDirectoryOffset) {
            throw new \RuntimeException('Existing APK Signing Block size is invalid');
        }
        $blockOffset = $centralDirectoryOffset - $totalSize;
        if ($this->readUInt64($apk, $blockOffset) !== $footerSize) {
            throw new \RuntimeException('Existing APK Signing Block sizes do not match');
        }

        $stripped = substr($apk, 0, $blockOffset) . substr($apk, $centralDirectoryOffset);
        $newEocdOffset = $zip['eocdOffset'] - $totalSize;
        return $this->replaceUInt32($stripped, $newEocdOffset + 16, $blockOffset);
    }

    private function parseZip(string $archive): array {
        $length = strlen($archive);
        if ($length < 22) {
            throw new \RuntimeException('APK is not a valid ZIP archive');
        }

        $minimumOffset = max(0, $length - 22 - 0xffff);
        $eocdOffset = null;
        for ($offset = $length - 22; $offset >= $minimumOffset; $offset--) {
            if (substr($archive, $offset, 4) !== self::ZIP_EOCD) {
                continue;
            }
            $commentLength = $this->readUInt16($archive, $offset + 20);
            if ($offset + 22 + $commentLength === $length) {
                $eocdOffset = $offset;
                break;
            }
        }
        if ($eocdOffset === null) {
            throw new \RuntimeException('APK ZIP End of Central Directory record was not found');
        }

        $diskNumber = $this->readUInt16($archive, $eocdOffset + 4);
        $centralDirectoryDisk = $this->readUInt16($archive, $eocdOffset + 6);
        $entriesOnDisk = $this->readUInt16($archive, $eocdOffset + 8);
        $totalEntries = $this->readUInt16($archive, $eocdOffset + 10);
        $centralDirectorySize = $this->readUInt32($archive, $eocdOffset + 12);
        $centralDirectoryOffset = $this->readUInt32($archive, $eocdOffset + 16);
        if ($diskNumber !== 0 || $centralDirectoryDisk !== 0 || $entriesOnDisk !== $totalEntries) {
            throw new \RuntimeException('Multi-disk APK ZIP archives are not supported');
        }
        if ($totalEntries === 0xffff
            || $centralDirectorySize === 0xffffffff
            || $centralDirectoryOffset === 0xffffffff
            || ($eocdOffset >= 20 && substr($archive, $eocdOffset - 20, 4) === "PK\x06\x07")) {
            throw new \RuntimeException('ZIP64 APKs are not supported');
        }
        if ($centralDirectoryOffset > $eocdOffset
            || $centralDirectorySize > $eocdOffset - $centralDirectoryOffset
            || $centralDirectoryOffset + $centralDirectorySize !== $eocdOffset) {
            throw new \RuntimeException('APK ZIP Central Directory bounds are invalid');
        }
        if ($totalEntries > 0
            && substr($archive, $centralDirectoryOffset, 4) !== self::ZIP_CENTRAL_DIRECTORY) {
            throw new \RuntimeException('APK ZIP Central Directory is malformed');
        }

        return [
            'eocdOffset' => $eocdOffset,
            'centralDirectoryOffset' => $centralDirectoryOffset,
            'centralDirectorySize' => $centralDirectorySize,
            'entryCount' => $totalEntries,
        ];
    }

    private function parseManifestMainAttributes(string $manifest): array {
        if (str_contains($manifest, "\x00")) {
            throw new \RuntimeException('Existing APK manifest contains a NUL byte');
        }
        $lines = preg_split('/\r\n|\n|\r/', $manifest);
        if ($lines === false) {
            throw new \RuntimeException('Unable to parse existing APK manifest');
        }

        $attributes = [];
        $attributeKeys = [];
        $currentName = null;
        $currentValue = '';
        $store = static function () use (&$attributes, &$attributeKeys, &$currentName, &$currentValue): void {
            if ($currentName === null) {
                return;
            }
            $key = "\x00" . strtolower($currentName);
            if (isset($attributeKeys[$key])) {
                throw new \RuntimeException("Duplicate APK manifest attribute: {$currentName}");
            }
            $attributeKeys[$key] = true;
            $attributes[] = ['name' => $currentName, 'value' => $currentValue];
            $currentName = null;
            $currentValue = '';
        };

        foreach ($lines as $line) {
            if ($line === '') {
                $store();
                break;
            }
            if ($line[0] === ' ') {
                if ($currentName === null) {
                    throw new \RuntimeException('Malformed continuation in existing APK manifest');
                }
                $currentValue .= substr($line, 1);
                continue;
            }
            $store();
            $separator = strpos($line, ':');
            if ($separator === false || $separator === 0) {
                throw new \RuntimeException('Malformed attribute in existing APK manifest');
            }
            $currentName = substr($line, 0, $separator);
            if (strlen($currentName) > 70
                || preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $currentName) !== 1) {
                throw new \RuntimeException("Invalid APK manifest attribute name: {$currentName}");
            }
            $currentValue = substr($line, $separator + 1);
            if (str_starts_with($currentValue, ' ')) {
                $currentValue = substr($currentValue, 1);
            }
        }
        $store();
        return $attributes;
    }

    private function jarHeader(string $name, string $value): string {
        if ($name === ''
            || strlen($name) > 70
            || preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $name) !== 1) {
            throw new \RuntimeException("Invalid JAR manifest attribute name: {$name}");
        }
        $line = $name . ': ' . $value;
        $length = strlen($line);
        if ($length === 0) {
            return "\r\n";
        }

        $take = min(70, $length);
        $output = substr($line, 0, $take);
        for ($offset = $take; $offset < $length;) {
            $take = min(69, $length - $offset);
            $output .= "\r\n " . substr($line, $offset, $take);
            $offset += $take;
        }
        return $output . "\r\n";
    }

    private function isV1DigestEntry(string $name): bool {
        return !str_ends_with($name, '/') && !$this->isRemovedEntry($name);
    }

    private function isRemovedEntry(string $name): bool {
        return $name === 'stamp-cert-sha256' || $this->isV1SignatureEntry($name);
    }

    private function isV1SignatureEntry(string $name): bool {
        if (!str_starts_with($name, 'META-INF/')) {
            return false;
        }
        $fileName = substr($name, 9);
        if ($fileName === '' || str_contains($fileName, '/')) {
            return false;
        }
        $lower = strtolower($fileName);
        return $lower === 'manifest.mf'
            || str_ends_with($lower, '.sf')
            || str_ends_with($lower, '.rsa')
            || str_ends_with($lower, '.dsa')
            || str_ends_with($lower, '.ec')
            || str_starts_with($lower, 'sig-');
    }

    private function validateEntryName(string $name): void {
        if ($name === ''
            || str_starts_with($name, '/')
            || str_contains($name, '\\')
            || str_contains($name, "\r")
            || str_contains($name, "\n")
            || str_contains($name, "\x00")) {
            throw new \RuntimeException("Unsafe APK ZIP entry name: {$name}");
        }
        $segments = explode('/', rtrim($name, '/'));
        if (in_array('', $segments, true)
            || in_array('.', $segments, true)
            || in_array('..', $segments, true)) {
            throw new \RuntimeException("Unsafe APK ZIP entry name: {$name}");
        }
    }

    private function safeSignerName(string $name): string {
        if ($name === '') {
            throw new \InvalidArgumentException('apkSignerName must not be empty');
        }
        $name = strtoupper(substr($name, 0, 8));
        return preg_replace('/[^A-Z0-9_-]/', '_', $name) ?? 'FOXY';
    }

    private function validateHeaderValue(string $value, string $name): void {
        if ($value === ''
            || str_contains($value, "\r")
            || str_contains($value, "\n")
            || str_contains($value, "\x00")) {
            throw new \InvalidArgumentException("{$name} must be a non-empty single-line string");
        }
    }

    private function signRawData(string $data, string $hashAlgo = 'sha256'): string {
        $digest = $this->rawHash($data, $hashAlgo);
        $signature = $this->signerKey->sign($digest, $hashAlgo);
        if (!$this->verifierKey->verify($digest, $signature, $hashAlgo)) {
            throw new \RuntimeException('Generated APK RSA signature did not verify');
        }
        return $signature;
    }

    private function rawHash(string $data, string $hashAlgo = 'sha256'): string {
        $digest = hex2bin(Hash::hash($hashAlgo, $data));
        if ($digest === false) {
            throw new \RuntimeException("Unable to encode {$hashAlgo} digest");
        }
        return $digest;
    }

    private function algorithmRecord(int $id, string $value): string {
        return $this->lengthPrefixed($this->uint32($id) . $this->lengthPrefixed($value));
    }

    private function attributeRecord(int $id, string $value): string {
        return $this->lengthPrefixed($this->uint32($id) . $value);
    }

    private function lengthPrefixed(string $value): string {
        $length = strlen($value);
        if ($length > 0x7fffffff) {
            throw new \RuntimeException('APK signing field is too large');
        }
        return $this->uint32($length) . $value;
    }

    private function uint32(int $value): string {
        if ($value < 0 || $value > 0xffffffff) {
            throw new \InvalidArgumentException('Value does not fit in an unsigned 32-bit integer');
        }
        return pack('V', $value);
    }

    private function uint64(int $value): string {
        if ($value < 0 || $value > 0x7fffffff) {
            throw new \InvalidArgumentException('APK signing length does not fit in a supported 64-bit field');
        }
        return pack('V2', $value, 0);
    }

    private function readUInt16(string $data, int $offset): int {
        if ($offset < 0 || $offset + 2 > strlen($data)) {
            throw new \RuntimeException('Truncated 16-bit APK ZIP field');
        }
        return unpack('vvalue', substr($data, $offset, 2))['value'];
    }

    private function readUInt32(string $data, int $offset): int {
        if ($offset < 0 || $offset + 4 > strlen($data)) {
            throw new \RuntimeException('Truncated 32-bit APK ZIP field');
        }
        return unpack('Vvalue', substr($data, $offset, 4))['value'];
    }

    private function readUInt64(string $data, int $offset): int {
        if ($offset < 0 || $offset + 8 > strlen($data)) {
            throw new \RuntimeException('Truncated 64-bit APK signing field');
        }
        $parts = unpack('Vlow/Vhigh', substr($data, $offset, 8));
        if ($parts['high'] !== 0) {
            throw new \RuntimeException('APK Signing Block is too large');
        }
        return $parts['low'];
    }

    private function replaceUInt16(string $data, int $offset, int $value): string {
        if ($value < 0 || $value > 0xffff || $offset < 0 || $offset + 2 > strlen($data)) {
            throw new \RuntimeException('Unable to update APK ZIP entry count');
        }
        return substr_replace($data, pack('v', $value), $offset, 2);
    }

    private function replaceUInt32(string $data, int $offset, int $value): string {
        if ($offset < 0 || $offset + 4 > strlen($data)) {
            throw new \RuntimeException('Unable to update APK ZIP Central Directory offset');
        }
        return substr_replace($data, $this->uint32($value), $offset, 4);
    }

    private function validateOptions(array $options): array {
        if (PHP_INT_SIZE < 8) {
            throw new \RuntimeException('APK signing requires 64-bit PHP');
        }
        if (!class_exists(ZipArchive::class)) {
            throw new \RuntimeException('APK signing requires the PHP zip extension');
        }
        if (array_key_exists('timestampUrl', $options)) {
            throw new \InvalidArgumentException('APK signatures do not support RFC 3161 timestamps');
        }

        $config = [
            'maxApkSize' => $this->integerOption($options, 'maxApkSize', self::DEFAULT_MAX_APK_SIZE),
            'maxZipEntries' => $this->integerOption($options, 'maxZipEntries', self::DEFAULT_MAX_ZIP_ENTRIES),
            'maxZipEntrySize' => $this->integerOption($options, 'maxZipEntrySize', self::DEFAULT_MAX_ZIP_ENTRY_SIZE),
            'maxZipTotalSize' => $this->integerOption($options, 'maxZipTotalSize', self::DEFAULT_MAX_ZIP_TOTAL_SIZE),
            'maxZipCompressionRatio' => $this->integerOption(
                $options,
                'maxZipCompressionRatio',
                self::DEFAULT_MAX_ZIP_RATIO
            ),
            'apkMinSdk' => $this->integerOption($options, 'apkMinSdk', 24),
            'apkCreatedBy' => $this->stringOption(
                $options,
                'apkCreatedBy',
                '1.0 (FoxySigningTool)'
            ),
            'apkSignerName' => $this->safeSignerName(
                $this->stringOption($options, 'apkSignerName', 'FOXY')
            ),
        ];
        $maxSdk = $this->integerOption($options, 'apkMaxSdk', 0x7fffffff);
        if ($maxSdk !== 0x7fffffff) {
            throw new \InvalidArgumentException('apkMaxSdk must be 2147483647 for single-signer APK v3');
        }
        if ($config['apkMinSdk'] > 0x7fffffff) {
            throw new \InvalidArgumentException('apkMinSdk must not exceed 2147483647');
        }
        if ($config['maxApkSize'] > 0xffffffff
            || $config['maxZipEntrySize'] > 0xffffffff
            || $config['maxZipTotalSize'] > 0xffffffff) {
            throw new \InvalidArgumentException('APK and ZIP size limits must not exceed 4294967295');
        }
        if ($config['maxZipEntries'] > 0xfffb) {
            throw new \InvalidArgumentException('maxZipEntries is too large for a non-ZIP64 signed APK');
        }
        if ($config['maxZipEntrySize'] > $config['maxZipTotalSize']) {
            throw new \InvalidArgumentException('maxZipEntrySize must not exceed maxZipTotalSize');
        }
        $this->validateHeaderValue($config['apkCreatedBy'], 'apkCreatedBy');
        return $config;
    }

    private function integerOption(array $options, string $name, int $default): int {
        if (!array_key_exists($name, $options)) {
            return $default;
        }
        if (!is_int($options[$name]) || $options[$name] < 1) {
            throw new \InvalidArgumentException("{$name} must be a positive integer");
        }
        return $options[$name];
    }

    private function stringOption(array $options, string $name, string $default): string {
        if (!array_key_exists($name, $options)) {
            return $default;
        }
        if (!is_string($options[$name])) {
            throw new \InvalidArgumentException("{$name} must be a string");
        }
        return $options[$name];
    }

    private function writeFileSafely(string $path, string $contents, ?int $mode): void {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            throw new \RuntimeException("Output directory does not exist: {$directory}");
        }
        if (is_dir($path)) {
            throw new \RuntimeException("APK output path is a directory: {$path}");
        }
        $temporary = tempnam($directory, '.foxy-sign-');
        if ($temporary === false) {
            throw new \RuntimeException("Unable to create temporary output beside: {$path}");
        }

        try {
            $written = @file_put_contents($temporary, $contents, LOCK_EX);
            if ($written !== strlen($contents)) {
                throw new \RuntimeException("Unable to write the complete signed APK: {$path}");
            }
            if ($mode !== null && !@chmod($temporary, $mode)) {
                throw new \RuntimeException("Unable to preserve APK output permissions: {$path}");
            }
            if (@rename($temporary, $path)) {
                $temporary = '';
                return;
            }

            if (!file_exists($path) || is_dir($path)) {
                throw new \RuntimeException("Unable to replace signed APK: {$path}");
            }
            $backup = tempnam($directory, '.foxy-backup-');
            if ($backup === false || !@unlink($backup) || !@rename($path, $backup)) {
                throw new \RuntimeException("Unable to replace signed APK: {$path}");
            }
            if (!@rename($temporary, $path)) {
                if (@rename($backup, $path)) {
                    throw new \RuntimeException("Unable to replace signed APK: {$path}");
                }
                throw new \RuntimeException(
                    "Unable to replace signed APK; original remains at: {$backup}"
                );
            }
            $temporary = '';
            if (!@unlink($backup)) {
                throw new \RuntimeException(
                    "Signed APK was written, but the old APK remains at: {$backup}"
                );
            }
        } finally {
            if ($temporary !== '') {
                @unlink($temporary);
            }
        }
    }
}
