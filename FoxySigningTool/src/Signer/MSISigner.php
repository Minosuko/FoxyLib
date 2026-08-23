<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{Hash, PEM, RSA, X509Certificate};
use FoxySigningTool\PKCS7;

final class MSISigner {
    private const CFB_MAGIC = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
    private const MAXREGSECT = 0xFFFFFFFA;
    private const DIFSECT = 0xFFFFFFFC;
    private const FATSECT = 0xFFFFFFFD;
    private const ENDOFCHAIN = 0xFFFFFFFE;
    private const FREESECT = 0xFFFFFFFF;
    private const NOSTREAM = 0xFFFFFFFF;
    private const DIR_STORAGE = 1;
    private const DIR_STREAM = 2;
    private const DIR_ROOT = 5;
    private const MINI_STREAM_CUTOFF = 4096;
    private const MINI_SECTOR_SIZE = 64;
    private const HEADER_DIFAT_ENTRIES = 109;

    private RSA $signerKey;
    private string $certPem;
    private string $hashAlgo;
    private array $extraCerts;
    private ?array $timestamp;

    public function __construct(
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        ?array $timestamp = null
    ) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('MSI signing requires an RSA private key');
        }
        $hashAlgo = strtolower(str_replace('-', '', $hashAlgo));
        if (!in_array($hashAlgo, ['sha1', 'sha256', 'sha384', 'sha512'], true)) {
            throw new \InvalidArgumentException('MSI signing supports SHA-1, SHA-256, SHA-384, and SHA-512');
        }

        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(
                PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY')
            );
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('MSI signing requires an RSA certificate', 0, $exception);
        }
        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('MSI signing key does not match the certificate');
        }
        foreach ($extraCerts as $extraCert) {
            if (!is_string($extraCert)) {
                throw new \InvalidArgumentException('Each extra certificate must be PEM encoded');
            }
            X509Certificate::fromPEM($extraCert);
        }

        $this->signerKey = $signerKey;
        $this->certPem = $certPem;
        $this->hashAlgo = $hashAlgo;
        $this->extraCerts = $extraCerts;
        $this->timestamp = $timestamp;
    }

    public static function fromPKCS12(string $pkcs12Path, string $password, string $hashAlgo = 'sha256'): self {
        $contents = @file_get_contents($pkcs12Path);
        if ($contents === false) {
            throw new \RuntimeException("Unable to read PKCS12 file: {$pkcs12Path}");
        }
        $pkcs12 = \FoxyCryptLib\FoxyCryptLib::pkcs12Decode($contents, $password);
        $keyInfo = $pkcs12['privateKeys'][0] ?? throw new \RuntimeException('No private key in PKCS12');
        $signerKey = PESigner::keyInfoToKey($keyInfo);
        if (!$signerKey instanceof RSA) {
            throw new \RuntimeException('MSI signing requires an RSA key in PKCS12');
        }

        $public = $signerKey->getPublicKey();
        $signerCertificate = null;
        $extraCerts = [];
        foreach ($pkcs12['certificates'] ?? [] as $certificateDer) {
            $certificatePem = PEM::encode($certificateDer, 'CERTIFICATE');
            try {
                $certificate = X509Certificate::fromDER($certificateDer);
                $certificateKey = RSA::fromPEM(
                    PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY')
                );
                $candidate = $certificateKey->getPublicKey();
                $matches = $public['n']->equals($candidate['n']) && $public['e']->equals($candidate['e']);
            } catch (\Throwable) {
                $matches = false;
            }
            if ($signerCertificate === null && $matches) {
                $signerCertificate = $certificatePem;
            } else {
                $extraCerts[] = $certificatePem;
            }
        }
        if ($signerCertificate === null) {
            throw new \RuntimeException('No certificate in PKCS12 matches the private key');
        }
        return new self($signerKey, $signerCertificate, $hashAlgo, $extraCerts);
    }

    public static function fromPEM(
        string $keyPem,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = []
    ): self {
        return new self(PESigner::loadKeyFromPEM($keyPem), $certPem, $hashAlgo, $extraCerts);
    }

    public function signFile(string $inputPath, ?string $outputPath = null): string {
        $msiData = @file_get_contents($inputPath);
        if ($msiData === false) {
            throw new \RuntimeException("Unable to read MSI file: {$inputPath}");
        }
        $outputPath ??= $inputPath;
        $permissions = @fileperms($inputPath);
        $mode = $permissions === false ? null : ($permissions & 0777);
        $this->writeFileSafely($outputPath, $this->signBinary($msiData), $mode);
        return $outputPath;
    }

    public function signBinary(string $msiData): string {
        $compound = $this->parseCompoundFile($msiData);
        $root = $compound['root'];
        $signatureTemplates = $this->removeSignatureStreams($root);
        $extendedDigest = $this->computeExtendedDigest($root);
        $digest = $this->computeMSIDigest($root, $extendedDigest);
        $signature = PKCS7::buildMSIAuthenticodeSignature(
            $digest,
            $this->signerKey,
            $this->certPem,
            $this->hashAlgo,
            $this->extraCerts,
            2,
            $this->authenticodeTimestamp()
        );
        $extendedName = $this->asciiToUtf16Le("\x05MsiDigitalSignatureEx");
        $signatureName = $this->asciiToUtf16Le("\x05DigitalSignature");
        $root['children'][] = $this->newStream(
            "\x05MsiDigitalSignatureEx",
            $extendedDigest,
            $signatureTemplates[$extendedName] ?? null
        );
        $root['children'][] = $this->newStream(
            "\x05DigitalSignature",
            $signature,
            $signatureTemplates[$signatureName] ?? null
        );
        return $this->buildCompoundFile($root, $compound['majorVersion'], $compound['minorVersion']);
    }

    public function signDetached(string $msiData): string {
        $compound = $this->parseCompoundFile($msiData);
        $root = $compound['root'];
        $this->removeSignatureStreams($root);
        return PKCS7::buildMSIAuthenticodeSignature(
            $this->computeMSIDigest($root),
            $this->signerKey,
            $this->certPem,
            $this->hashAlgo,
            $this->extraCerts,
            1,
            $this->authenticodeTimestamp()
        );
    }

    private function authenticodeTimestamp(): ?array {
        if ($this->timestamp === null) {
            return null;
        }
        return $this->timestamp + [
            'attributeOid' => \FoxySigningTool\TimestampClient::OID_AUTHENTICODE_TIMESTAMP,
        ];
    }

    private function parseCompoundFile(string $data): array {
        if (strlen($data) < 512 || substr($data, 0, 8) !== self::CFB_MAGIC) {
            throw new \RuntimeException('Not an OLE compound document (MSI)');
        }
        $minorVersion = $this->readUInt16($data, 0x18, 'minor version');
        $majorVersion = $this->readUInt16($data, 0x1A, 'major version');
        if ($majorVersion !== 3 && $majorVersion !== 4) {
            throw new \RuntimeException('Unsupported CFB major version');
        }
        if ($this->readUInt16($data, 0x1C, 'byte order') !== 0xFFFE) {
            throw new \RuntimeException('Unsupported CFB byte order');
        }
        $sectorShift = $this->readUInt16($data, 0x1E, 'sector shift');
        if (($majorVersion === 3 && $sectorShift !== 9)
            || ($majorVersion === 4 && $sectorShift !== 12)) {
            throw new \RuntimeException('Invalid CFB sector size');
        }
        if ($this->readUInt16($data, 0x20, 'mini sector shift') !== 6
            || $this->readUInt32($data, 0x38, 'mini stream cutoff') !== self::MINI_STREAM_CUTOFF) {
            throw new \RuntimeException('Unsupported CFB mini stream layout');
        }

        $sectorSize = 1 << $sectorShift;
        if (strlen($data) < $sectorSize * 3 || strlen($data) % $sectorSize !== 0) {
            throw new \RuntimeException('CFB file is not sector aligned');
        }
        $sectorCount = intdiv(strlen($data), $sectorSize) - 1;
        $numDirectorySectors = $this->readUInt32($data, 0x28, 'directory sector count');
        if ($majorVersion === 3 && $numDirectorySectors !== 0) {
            throw new \RuntimeException('Version 3 CFB declares directory sector count');
        }
        $numFatSectors = $this->readUInt32($data, 0x2C, 'FAT sector count');
        if ($numFatSectors < 1 || $numFatSectors > $sectorCount) {
            throw new \RuntimeException('Invalid CFB FAT sector count');
        }
        $firstDirectorySector = $this->readUInt32($data, 0x30, 'first directory sector');
        $firstMiniFatSector = $this->readUInt32($data, 0x3C, 'first miniFAT sector');
        $numMiniFatSectors = $this->readUInt32($data, 0x40, 'miniFAT sector count');
        $firstDifatSector = $this->readUInt32($data, 0x44, 'first DIFAT sector');
        $numDifatSectors = $this->readUInt32($data, 0x48, 'DIFAT sector count');

        $fatSectorIds = [];
        for ($i = 0; $i < self::HEADER_DIFAT_ENTRIES; $i++) {
            $sector = $this->readUInt32($data, 0x4C + $i * 4, 'header DIFAT entry');
            if ($sector === self::FREESECT) {
                continue;
            }
            $this->assertRegularSector($sector, $sectorCount, 'header DIFAT entry');
            $fatSectorIds[] = $sector;
        }
        if (count($fatSectorIds) > $numFatSectors) {
            throw new \RuntimeException('CFB header contains excess FAT sectors');
        }

        $difatSectorIds = [];
        $currentDifat = $firstDifatSector;
        $difatEntriesPerSector = intdiv($sectorSize, 4) - 1;
        for ($i = 0; $i < $numDifatSectors; $i++) {
            $this->assertRegularSector($currentDifat, $sectorCount, 'DIFAT chain');
            if (isset($difatSectorIds[$currentDifat])) {
                throw new \RuntimeException('Cycle in CFB DIFAT chain');
            }
            $difatSectorIds[$currentDifat] = true;
            $sectorData = $this->readSector($data, $sectorSize, $sectorCount, $currentDifat);
            for ($j = 0; $j < $difatEntriesPerSector; $j++) {
                $sector = $this->readUInt32($sectorData, $j * 4, 'DIFAT entry');
                if ($sector === self::FREESECT) {
                    continue;
                }
                $this->assertRegularSector($sector, $sectorCount, 'DIFAT FAT entry');
                $fatSectorIds[] = $sector;
            }
            $currentDifat = $this->readUInt32(
                $sectorData,
                $sectorSize - 4,
                'next DIFAT sector'
            );
        }
        if ($numDifatSectors === 0) {
            if ($firstDifatSector !== self::ENDOFCHAIN && $firstDifatSector !== self::FREESECT) {
                throw new \RuntimeException('CFB declares an unexpected DIFAT chain');
            }
        } elseif ($currentDifat !== self::ENDOFCHAIN) {
            throw new \RuntimeException('CFB DIFAT chain is longer than declared');
        }
        if (count($fatSectorIds) !== $numFatSectors
            || count(array_unique($fatSectorIds)) !== count($fatSectorIds)) {
            throw new \RuntimeException('CFB FAT sector list is inconsistent');
        }

        $fat = [];
        foreach ($fatSectorIds as $sectorId) {
            $fat = array_merge(
                $fat,
                array_values(unpack('V*', $this->readSector($data, $sectorSize, $sectorCount, $sectorId)))
            );
        }
        if (count($fat) < $sectorCount) {
            throw new \RuntimeException('CFB FAT does not cover the file');
        }
        foreach ($fatSectorIds as $sectorId) {
            if (($fat[$sectorId] ?? null) !== self::FATSECT) {
                throw new \RuntimeException('CFB FAT sector is not marked FATSECT');
            }
        }
        foreach (array_keys($difatSectorIds) as $sectorId) {
            if (($fat[$sectorId] ?? null) !== self::DIFSECT) {
                throw new \RuntimeException('CFB DIFAT sector is not marked DIFSECT');
            }
        }

        $context = [
            'data' => $data,
            'sectorSize' => $sectorSize,
            'sectorCount' => $sectorCount,
            'fat' => $fat,
            'claimedRegular' => [],
            'claimedMini' => [],
        ];
        foreach ($fatSectorIds as $sectorId) {
            $context['claimedRegular'][$sectorId] = 'FAT';
        }
        foreach (array_keys($difatSectorIds) as $sectorId) {
            $context['claimedRegular'][$sectorId] = 'DIFAT';
        }

        $directoryData = $this->readRegularChain(
            $context,
            $firstDirectorySector,
            null,
            'directory'
        );
        if ($majorVersion === 4
            && intdiv(strlen($directoryData), $sectorSize) !== $numDirectorySectors) {
            throw new \RuntimeException('CFB directory sector count is inconsistent');
        }
        $entries = $this->parseDirectoryEntries($directoryData, $majorVersion);
        if (!isset($entries[0]) || $entries[0] === null || $entries[0]['type'] !== self::DIR_ROOT) {
            throw new \RuntimeException('CFB root directory entry is missing');
        }
        if ($entries[0]['name'] !== $this->asciiToUtf16Le('Root Entry')) {
            throw new \RuntimeException('Invalid CFB root directory name');
        }
        if (!$this->isMsiRootClsid($entries[0]['clsid'])) {
            throw new \RuntimeException('Compound document is not an MSI, MST, or MSP package');
        }

        if ($numMiniFatSectors === 0) {
            if ($firstMiniFatSector !== self::ENDOFCHAIN && $firstMiniFatSector !== self::FREESECT) {
                throw new \RuntimeException('CFB declares an unexpected miniFAT chain');
            }
            $context['miniFat'] = [];
        } else {
            $miniFatData = $this->readRegularChain(
                $context,
                $firstMiniFatSector,
                $numMiniFatSectors * $sectorSize,
                'miniFAT'
            );
            $context['miniFat'] = array_values(unpack('V*', $miniFatData));
        }
        $context['miniStream'] = $this->readRegularChain(
            $context,
            $entries[0]['startSector'],
            $entries[0]['size'],
            'root mini stream'
        );

        $visited = [0 => true];
        $root = $this->entryToNode($entries[0], $context, true);
        $root['children'] = $this->readSiblingTree($entries[0]['child'], $entries, $context, $visited);
        $this->validateChildNames($root['children']);
        foreach ($entries as $id => $entry) {
            if ($entry !== null && !isset($visited[$id])) {
                throw new \RuntimeException("Unreachable CFB directory entry: {$id}");
            }
        }

        return [
            'root' => $root,
            'majorVersion' => $majorVersion,
            'minorVersion' => $minorVersion,
        ];
    }

    private function parseDirectoryEntries(string $directoryData, int $majorVersion): array {
        if (strlen($directoryData) === 0 || strlen($directoryData) % 128 !== 0) {
            throw new \RuntimeException('Invalid CFB directory stream length');
        }
        $entries = [];
        for ($offset = 0; $offset < strlen($directoryData); $offset += 128) {
            $entry = substr($directoryData, $offset, 128);
            $type = ord($entry[0x42]);
            if ($type === 0) {
                $entries[] = null;
                continue;
            }
            if (!in_array($type, [self::DIR_STORAGE, self::DIR_STREAM, self::DIR_ROOT], true)) {
                throw new \RuntimeException('Invalid CFB directory entry type');
            }
            $nameLength = $this->readUInt16($entry, 0x40, 'directory name length');
            if ($nameLength < 2 || $nameLength > 64 || ($nameLength & 1) !== 0
                || substr($entry, $nameLength - 2, 2) !== "\x00\x00") {
                throw new \RuntimeException('Invalid CFB directory entry name');
            }
            $color = ord($entry[0x43]);
            if ($color !== 0 && $color !== 1) {
                throw new \RuntimeException('Invalid CFB directory entry color');
            }
            $sizeLow = $this->readUInt32($entry, 0x78, 'stream size');
            $sizeHigh = $this->readUInt32($entry, 0x7C, 'stream size');
            if ($majorVersion === 3 && $sizeHigh !== 0) {
                throw new \RuntimeException('Version 3 CFB stream has a 64-bit size');
            }
            $size = $this->combineUInt64($sizeLow, $sizeHigh, 'stream size');
            if ($type === self::DIR_STORAGE && $size !== 0) {
                throw new \RuntimeException('CFB storage entry has a stream size');
            }
            $entries[] = [
                'id' => intdiv($offset, 128),
                'name' => substr($entry, 0, $nameLength - 2),
                'type' => $type,
                'color' => $color,
                'left' => $this->readUInt32($entry, 0x44, 'left sibling'),
                'right' => $this->readUInt32($entry, 0x48, 'right sibling'),
                'child' => $this->readUInt32($entry, 0x4C, 'child entry'),
                'clsid' => substr($entry, 0x50, 16),
                'stateBits' => substr($entry, 0x60, 4),
                'creationTime' => substr($entry, 0x64, 8),
                'modifiedTime' => substr($entry, 0x6C, 8),
                'startSector' => $this->readUInt32($entry, 0x74, 'stream start sector'),
                'size' => $size,
            ];
        }
        return $entries;
    }

    private function readSiblingTree(
        int $entryId,
        array $entries,
        array &$context,
        array &$visited,
        int $depth = 0
    ): array {
        $nodes = [];
        $this->appendSiblingTree($entryId, $entries, $context, $visited, $nodes, $depth);
        return $nodes;
    }

    private function appendSiblingTree(
        int $entryId,
        array $entries,
        array &$context,
        array &$visited,
        array &$nodes,
        int $depth
    ): void {
        if ($entryId === self::NOSTREAM) {
            return;
        }
        if ($depth > 256) {
            throw new \RuntimeException('CFB directory hierarchy is too deep');
        }
        if ($entryId === 0 || !isset($entries[$entryId]) || $entries[$entryId] === null) {
            throw new \RuntimeException('Invalid CFB directory tree reference');
        }
        if (isset($visited[$entryId])) {
            throw new \RuntimeException('Cycle or cross-link in CFB directory tree');
        }
        $visited[$entryId] = true;
        $entry = $entries[$entryId];
        if ($entry['type'] === self::DIR_ROOT) {
            throw new \RuntimeException('Nested CFB root directory entry');
        }

        $this->appendSiblingTree($entry['left'], $entries, $context, $visited, $nodes, $depth + 1);
        $node = $this->entryToNode($entry, $context, false);
        if ($entry['type'] === self::DIR_STORAGE) {
            $node['children'] = $this->readSiblingTree(
                $entry['child'],
                $entries,
                $context,
                $visited,
                $depth + 1
            );
            $this->validateChildNames($node['children']);
        } elseif ($entry['child'] !== self::NOSTREAM) {
            throw new \RuntimeException('CFB stream directory entry has children');
        }
        $nodes[] = $node;
        $this->appendSiblingTree($entry['right'], $entries, $context, $visited, $nodes, $depth + 1);
    }

    private function entryToNode(array $entry, array &$context, bool $isRoot): array {
        $node = [
            'id' => $entry['id'],
            'name' => $entry['name'],
            'type' => $entry['type'],
            'color' => $entry['color'],
            'left' => $entry['left'],
            'right' => $entry['right'],
            'child' => $entry['child'],
            'clsid' => $entry['clsid'],
            'stateBits' => $entry['stateBits'],
            'creationTime' => $entry['creationTime'],
            'modifiedTime' => $entry['modifiedTime'],
            'children' => [],
        ];
        if ($entry['type'] === self::DIR_STREAM) {
            $node['data'] = $this->readEntryStream($entry, $context);
        } elseif (!$isRoot && $entry['type'] !== self::DIR_STORAGE) {
            throw new \RuntimeException('Invalid CFB hierarchy');
        }
        return $node;
    }

    private function readEntryStream(array $entry, array &$context): string {
        if ($entry['size'] === 0) {
            if ($entry['startSector'] !== self::ENDOFCHAIN && $entry['startSector'] !== self::FREESECT) {
                throw new \RuntimeException('Empty CFB stream has an allocated sector');
            }
            return '';
        }
        if ($entry['size'] < self::MINI_STREAM_CUTOFF) {
            return $this->readMiniChain($context, $entry['startSector'], $entry['size']);
        }
        return $this->readRegularChain(
            $context,
            $entry['startSector'],
            $entry['size'],
            'stream ' . bin2hex($entry['name'])
        );
    }

    private function readRegularChain(
        array &$context,
        int $startSector,
        ?int $size,
        string $label
    ): string {
        if ($size === 0) {
            if ($startSector !== self::ENDOFCHAIN && $startSector !== self::FREESECT) {
                throw new \RuntimeException("Empty {$label} has an allocated sector");
            }
            return '';
        }
        $expectedSectors = $size === null ? null : intdiv($size + $context['sectorSize'] - 1, $context['sectorSize']);
        $chunks = [];
        $sector = $startSector;
        $seen = [];
        while ($sector !== self::ENDOFCHAIN) {
            $this->assertRegularSector($sector, $context['sectorCount'], $label);
            if (isset($seen[$sector])) {
                throw new \RuntimeException("Cycle in CFB {$label} chain");
            }
            if (isset($context['claimedRegular'][$sector])) {
                throw new \RuntimeException("Cross-link in CFB {$label} chain");
            }
            $seen[$sector] = true;
            $context['claimedRegular'][$sector] = $label;
            $chunks[] = $this->readSector(
                $context['data'],
                $context['sectorSize'],
                $context['sectorCount'],
                $sector
            );
            if ($expectedSectors !== null && count($chunks) > $expectedSectors) {
                throw new \RuntimeException("CFB {$label} chain is longer than its stream size");
            }
            $next = $context['fat'][$sector] ?? self::FREESECT;
            if ($next !== self::ENDOFCHAIN && $next >= self::MAXREGSECT) {
                throw new \RuntimeException("Invalid sector marker in CFB {$label} chain");
            }
            $sector = $next;
        }
        if (count($chunks) === 0
            || ($expectedSectors !== null && count($chunks) !== $expectedSectors)) {
            throw new \RuntimeException("CFB {$label} chain is shorter than its stream size");
        }
        $result = implode('', $chunks);
        return $size === null ? $result : substr($result, 0, $size);
    }

    private function readMiniChain(array &$context, int $startSector, int $size): string {
        $expectedSectors = intdiv($size + self::MINI_SECTOR_SIZE - 1, self::MINI_SECTOR_SIZE);
        $result = '';
        $sector = $startSector;
        $seen = [];
        for ($i = 0; $i < $expectedSectors; $i++) {
            if ($sector >= self::MAXREGSECT || !isset($context['miniFat'][$sector])) {
                throw new \RuntimeException('Invalid CFB mini stream sector');
            }
            if (isset($seen[$sector]) || isset($context['claimedMini'][$sector])) {
                throw new \RuntimeException('Cycle or cross-link in CFB mini stream');
            }
            $seen[$sector] = true;
            $context['claimedMini'][$sector] = true;
            $offset = $sector * self::MINI_SECTOR_SIZE;
            if ($offset > strlen($context['miniStream']) - self::MINI_SECTOR_SIZE) {
                throw new \RuntimeException('CFB mini stream sector is outside the root mini stream');
            }
            $result .= substr($context['miniStream'], $offset, self::MINI_SECTOR_SIZE);
            $sector = $context['miniFat'][$sector];
            if ($i + 1 < $expectedSectors && $sector >= self::MAXREGSECT) {
                throw new \RuntimeException('CFB mini stream chain is shorter than its stream size');
            }
        }
        if ($sector !== self::ENDOFCHAIN) {
            throw new \RuntimeException('CFB mini stream chain is longer than its stream size');
        }
        return substr($result, 0, $size);
    }

    private function removeSignatureStreams(array &$root): array {
        $removed = [];
        foreach ($root['children'] as $child) {
            if ($this->isSignatureName($child['name'])) {
                if ($child['type'] !== self::DIR_STREAM) {
                    throw new \RuntimeException('Reserved MSI signature entry is not a stream');
                }
                $removed[$child['name']] = $child;
            }
        }
        $root['children'] = array_values(array_filter(
            $root['children'],
            fn(array $child): bool => !$this->isSignatureName($child['name'])
        ));
        return $removed;
    }

    private function computeMSIDigest(array $root, ?string $extendedDigest = null): string {
        $hashInput = '';
        $this->appendStorageHashInput($root, true, $hashInput);
        if ($extendedDigest !== null) {
            $hashInput = $extendedDigest . $hashInput;
        }
        return hex2bin(Hash::hash($this->hashAlgo, $hashInput));
    }

    private function computeExtendedDigest(array $root): string {
        $hashInput = '';
        $this->appendStorageMetadataHashInput($root, true, $hashInput);
        return hex2bin(Hash::hash($this->hashAlgo, $hashInput));
    }

    private function appendStorageMetadataHashInput(array $storage, bool $isRoot, string &$hashInput): void {
        $this->appendNodeMetadata($storage, $isRoot, $hashInput);
        $children = $storage['children'];
        usort($children, fn(array $a, array $b): int => $this->compareHashNames($a['name'], $b['name']));
        foreach ($children as $child) {
            if ($isRoot && $this->isSignatureName($child['name'])) {
                continue;
            }
            if ($child['type'] === self::DIR_STREAM) {
                $this->appendNodeMetadata($child, false, $hashInput);
            } elseif ($child['type'] === self::DIR_STORAGE) {
                $this->appendStorageMetadataHashInput($child, false, $hashInput);
            } else {
                throw new \RuntimeException('Invalid CFB node while hashing MSI metadata');
            }
        }
    }

    private function appendNodeMetadata(array $node, bool $isRoot, string &$hashInput): void {
        if (!$isRoot) {
            $hashInput .= $node['name'];
        }
        if ($node['type'] === self::DIR_STREAM) {
            $hashInput .= pack('V', strlen($node['data']));
        } else {
            $hashInput .= $node['clsid'];
        }
        $hashInput .= $node['stateBits'];
        if (!$isRoot) {
            $hashInput .= $node['creationTime'] . $node['modifiedTime'];
        }
    }

    private function appendStorageHashInput(array $storage, bool $isRoot, string &$hashInput): void {
        $children = $storage['children'];
        usort($children, fn(array $a, array $b): int => $this->compareHashNames($a['name'], $b['name']));
        foreach ($children as $child) {
            if ($isRoot && $this->isSignatureName($child['name'])) {
                continue;
            }
            if ($child['type'] === self::DIR_STREAM) {
                $hashInput .= $child['data'];
            } elseif ($child['type'] === self::DIR_STORAGE) {
                $this->appendStorageHashInput($child, false, $hashInput);
            } else {
                throw new \RuntimeException('Invalid CFB node while hashing MSI');
            }
        }
        $hashInput .= $storage['clsid'];
    }

    private function buildCompoundFile(array $root, int $majorVersion, int $minorVersion): string {
        $sectorSize = $majorVersion === 4 ? 4096 : 512;
        $preserveDirectoryTree = $this->hasCompleteDirectoryLayout($root);
        if (!$preserveDirectoryTree) {
            $this->sortStorageTree($root);
            $nextId = 0;
            $this->assignDirectoryIds($root, $nextId);
        }

        $miniStream = '';
        $miniFat = [];
        $this->allocateMiniStreams($root, $miniStream, $miniFat);

        $sectors = [];
        $fat = [];
        $root['size'] = strlen($miniStream);
        $root['startSector'] = $this->allocateRegularData($miniStream, $sectorSize, $sectors, $fat);
        $this->allocateRegularStreams($root, $sectorSize, $sectors, $fat);

        if ($miniFat === []) {
            $firstMiniFatSector = self::ENDOFCHAIN;
            $numMiniFatSectors = 0;
        } else {
            $miniFatData = '';
            foreach ($miniFat as $entry) {
                $miniFatData .= pack('V', $entry);
            }
            $numMiniFatSectors = intdiv(strlen($miniFatData) + $sectorSize - 1, $sectorSize);
            $miniFatData = str_pad($miniFatData, $numMiniFatSectors * $sectorSize, "\xFF");
            $firstMiniFatSector = $this->allocateRegularData($miniFatData, $sectorSize, $sectors, $fat);
        }

        if (!$preserveDirectoryTree) {
            $this->assignDirectoryLinks($root, true);
        }
        $flatEntries = [];
        $this->collectDirectoryEntries($root, $flatEntries);
        ksort($flatEntries, SORT_NUMERIC);
        $directoryData = '';
        foreach ($flatEntries as $entry) {
            $directoryData .= $this->encodeDirectoryEntry($entry);
        }
        $unusedEntry = str_repeat("\x00", 128);
        $unusedEntry = substr_replace($unusedEntry, pack('V', self::NOSTREAM), 0x44, 4);
        $unusedEntry = substr_replace($unusedEntry, pack('V', self::NOSTREAM), 0x48, 4);
        $unusedEntry = substr_replace($unusedEntry, pack('V', self::NOSTREAM), 0x4C, 4);
        while (strlen($directoryData) % $sectorSize !== 0) {
            $directoryData .= $unusedEntry;
        }
        $numDirectorySectors = intdiv(strlen($directoryData), $sectorSize);
        $firstDirectorySector = $this->allocateRegularData($directoryData, $sectorSize, $sectors, $fat);

        $baseSectorCount = count($sectors);
        $fatEntriesPerSector = intdiv($sectorSize, 4);
        $numFatSectors = max(1, intdiv($baseSectorCount + $fatEntriesPerSector - 1, $fatEntriesPerSector));
        $numDifatSectors = 0;
        for ($i = 0; $i < 32; $i++) {
            $newDifatSectors = $numFatSectors > self::HEADER_DIFAT_ENTRIES
                ? intdiv(
                    $numFatSectors - self::HEADER_DIFAT_ENTRIES + ($fatEntriesPerSector - 2),
                    $fatEntriesPerSector - 1
                )
                : 0;
            $newFatSectors = intdiv(
                $baseSectorCount + $numFatSectors + $newDifatSectors + $fatEntriesPerSector - 1,
                $fatEntriesPerSector
            );
            if ($newFatSectors === $numFatSectors && $newDifatSectors === $numDifatSectors) {
                break;
            }
            $numFatSectors = $newFatSectors;
            $numDifatSectors = $newDifatSectors;
            if ($i === 31) {
                throw new \RuntimeException('Unable to stabilize CFB FAT layout');
            }
        }

        $fatSectorIds = [];
        for ($i = 0; $i < $numFatSectors; $i++) {
            $sectorId = count($sectors);
            $fatSectorIds[] = $sectorId;
            $sectors[] = '';
            $fat[$sectorId] = self::FATSECT;
        }
        $difatSectorIds = [];
        for ($i = 0; $i < $numDifatSectors; $i++) {
            $sectorId = count($sectors);
            $difatSectorIds[] = $sectorId;
            $sectors[] = '';
            $fat[$sectorId] = self::DIFSECT;
        }

        $totalSectors = count($sectors);
        $fatValues = array_fill(0, $numFatSectors * $fatEntriesPerSector, self::FREESECT);
        foreach ($fat as $sectorId => $nextSector) {
            if ($sectorId < 0 || $sectorId >= $totalSectors) {
                throw new \RuntimeException('Internal CFB FAT allocation error');
            }
            $fatValues[$sectorId] = $nextSector;
        }
        for ($i = 0; $i < $numFatSectors; $i++) {
            $sectorData = '';
            $start = $i * $fatEntriesPerSector;
            for ($j = 0; $j < $fatEntriesPerSector; $j++) {
                $sectorData .= pack('V', $fatValues[$start + $j]);
            }
            $sectors[$fatSectorIds[$i]] = $sectorData;
        }

        $remainingFatIds = array_slice($fatSectorIds, self::HEADER_DIFAT_ENTRIES);
        $difatCapacity = $fatEntriesPerSector - 1;
        foreach ($difatSectorIds as $index => $sectorId) {
            $sectorData = '';
            for ($i = 0; $i < $difatCapacity; $i++) {
                $sectorData .= pack('V', array_shift($remainingFatIds) ?? self::FREESECT);
            }
            $sectorData .= pack(
                'V',
                $difatSectorIds[$index + 1] ?? self::ENDOFCHAIN
            );
            $sectors[$sectorId] = $sectorData;
        }
        if ($remainingFatIds !== []) {
            throw new \RuntimeException('Internal CFB DIFAT allocation error');
        }

        $header = self::CFB_MAGIC
            . str_repeat("\x00", 16)
            . pack('v', $minorVersion)
            . pack('v', $majorVersion)
            . pack('v', 0xFFFE)
            . pack('v', $majorVersion === 4 ? 12 : 9)
            . pack('v', 6)
            . str_repeat("\x00", 6)
            . pack('V', $majorVersion === 4 ? $numDirectorySectors : 0)
            . pack('V', $numFatSectors)
            . pack('V', $firstDirectorySector)
            . pack('V', 0)
            . pack('V', self::MINI_STREAM_CUTOFF)
            . pack('V', $firstMiniFatSector)
            . pack('V', $numMiniFatSectors)
            . pack('V', $difatSectorIds[0] ?? self::ENDOFCHAIN)
            . pack('V', $numDifatSectors);
        for ($i = 0; $i < self::HEADER_DIFAT_ENTRIES; $i++) {
            $header .= pack('V', $fatSectorIds[$i] ?? self::FREESECT);
        }
        if (strlen($header) !== 512) {
            throw new \RuntimeException('Internal CFB header encoding error');
        }
        $output = str_pad($header, $sectorSize, "\x00");
        foreach ($sectors as $sector) {
            if (strlen($sector) !== $sectorSize) {
                throw new \RuntimeException('Internal CFB sector encoding error');
            }
            $output .= $sector;
        }
        return $output;
    }

    private function sortStorageTree(array &$storage): void {
        usort($storage['children'], fn(array $a, array $b): int => $this->compareTreeNames($a['name'], $b['name']));
        foreach ($storage['children'] as &$child) {
            if ($child['type'] === self::DIR_STORAGE) {
                $this->sortStorageTree($child);
            }
        }
        unset($child);
    }

    private function assignDirectoryIds(array &$node, int &$nextId): void {
        $node['id'] = $nextId++;
        foreach ($node['children'] as &$child) {
            $this->assignDirectoryIds($child, $nextId);
        }
        unset($child);
    }

    private function allocateMiniStreams(array &$storage, string &$miniStream, array &$miniFat): void {
        foreach ($storage['children'] as &$child) {
            if ($child['type'] === self::DIR_STORAGE) {
                $this->allocateMiniStreams($child, $miniStream, $miniFat);
                continue;
            }
            $size = strlen($child['data']);
            $child['size'] = $size;
            if ($size === 0) {
                $child['startSector'] = self::ENDOFCHAIN;
                continue;
            }
            if ($size >= self::MINI_STREAM_CUTOFF) {
                continue;
            }
            $count = intdiv($size + self::MINI_SECTOR_SIZE - 1, self::MINI_SECTOR_SIZE);
            $start = count($miniFat);
            $child['startSector'] = $start;
            for ($i = 0; $i < $count; $i++) {
                $miniFat[] = $i + 1 === $count ? self::ENDOFCHAIN : $start + $i + 1;
                $miniStream .= str_pad(
                    substr($child['data'], $i * self::MINI_SECTOR_SIZE, self::MINI_SECTOR_SIZE),
                    self::MINI_SECTOR_SIZE,
                    "\x00"
                );
            }
        }
        unset($child);
    }

    private function allocateRegularStreams(
        array &$storage,
        int $sectorSize,
        array &$sectors,
        array &$fat
    ): void {
        foreach ($storage['children'] as &$child) {
            if ($child['type'] === self::DIR_STORAGE) {
                $this->allocateRegularStreams($child, $sectorSize, $sectors, $fat);
            } elseif ($child['size'] >= self::MINI_STREAM_CUTOFF) {
                $child['startSector'] = $this->allocateRegularData(
                    $child['data'],
                    $sectorSize,
                    $sectors,
                    $fat
                );
            }
        }
        unset($child);
    }

    private function allocateRegularData(
        string $data,
        int $sectorSize,
        array &$sectors,
        array &$fat
    ): int {
        if ($data === '') {
            return self::ENDOFCHAIN;
        }
        $count = intdiv(strlen($data) + $sectorSize - 1, $sectorSize);
        $start = count($sectors);
        for ($i = 0; $i < $count; $i++) {
            $sectorId = count($sectors);
            $sectors[] = str_pad(substr($data, $i * $sectorSize, $sectorSize), $sectorSize, "\x00");
            $fat[$sectorId] = $i + 1 === $count ? self::ENDOFCHAIN : $sectorId + 1;
        }
        return $start;
    }

    private function assignDirectoryLinks(array &$storage, bool $isRoot = false): void {
        if ($isRoot) {
            $storage['left'] = self::NOSTREAM;
            $storage['right'] = self::NOSTREAM;
            $storage['color'] = 1;
        }
        [$storage['child'], $links] = $this->buildSiblingTree($storage['children']);
        foreach ($storage['children'] as &$child) {
            $link = $links[$child['id']];
            $child['left'] = $link['left'];
            $child['right'] = $link['right'];
            $child['color'] = $link['color'];
            if ($child['type'] === self::DIR_STORAGE) {
                $this->assignDirectoryLinks($child);
            } else {
                $child['child'] = self::NOSTREAM;
            }
        }
        unset($child);
    }

    private function buildSiblingTree(array $children): array {
        if ($children === []) {
            return [self::NOSTREAM, []];
        }
        $links = [];
        $names = [];
        $root = self::NOSTREAM;
        foreach ($children as $child) {
            $id = $child['id'];
            $names[$id] = $child['name'];
            $links[$id] = [
                'left' => self::NOSTREAM,
                'right' => self::NOSTREAM,
                'parent' => self::NOSTREAM,
                'color' => 0,
            ];
            $parent = self::NOSTREAM;
            $cursor = $root;
            while ($cursor !== self::NOSTREAM) {
                $parent = $cursor;
                $cursor = $this->compareTreeNames($child['name'], $names[$cursor]) < 0
                    ? $links[$cursor]['left']
                    : $links[$cursor]['right'];
            }
            $links[$id]['parent'] = $parent;
            if ($parent === self::NOSTREAM) {
                $root = $id;
            } elseif ($this->compareTreeNames($child['name'], $names[$parent]) < 0) {
                $links[$parent]['left'] = $id;
            } else {
                $links[$parent]['right'] = $id;
            }
            $this->repairSiblingTreeAfterInsert($links, $root, $id);
        }
        $links[$root]['color'] = 1;
        return [$root, $links];
    }

    private function repairSiblingTreeAfterInsert(array &$links, int &$root, int $node): void {
        while ($this->treeColor($links, $links[$node]['parent']) === 0) {
            $parent = $links[$node]['parent'];
            $grandparent = $links[$parent]['parent'];
            if ($parent === $links[$grandparent]['left']) {
                $uncle = $links[$grandparent]['right'];
                if ($this->treeColor($links, $uncle) === 0) {
                    $links[$parent]['color'] = 1;
                    $links[$uncle]['color'] = 1;
                    $links[$grandparent]['color'] = 0;
                    $node = $grandparent;
                    continue;
                }
                if ($node === $links[$parent]['right']) {
                    $node = $parent;
                    $this->rotateSiblingTreeLeft($links, $root, $node);
                    $parent = $links[$node]['parent'];
                    $grandparent = $links[$parent]['parent'];
                }
                $links[$parent]['color'] = 1;
                $links[$grandparent]['color'] = 0;
                $this->rotateSiblingTreeRight($links, $root, $grandparent);
            } else {
                $uncle = $links[$grandparent]['left'];
                if ($this->treeColor($links, $uncle) === 0) {
                    $links[$parent]['color'] = 1;
                    $links[$uncle]['color'] = 1;
                    $links[$grandparent]['color'] = 0;
                    $node = $grandparent;
                    continue;
                }
                if ($node === $links[$parent]['left']) {
                    $node = $parent;
                    $this->rotateSiblingTreeRight($links, $root, $node);
                    $parent = $links[$node]['parent'];
                    $grandparent = $links[$parent]['parent'];
                }
                $links[$parent]['color'] = 1;
                $links[$grandparent]['color'] = 0;
                $this->rotateSiblingTreeLeft($links, $root, $grandparent);
            }
        }
        $links[$root]['color'] = 1;
    }

    private function rotateSiblingTreeLeft(array &$links, int &$root, int $node): void {
        $pivot = $links[$node]['right'];
        if ($pivot === self::NOSTREAM) {
            throw new \RuntimeException('Internal CFB directory tree rotation error');
        }
        $links[$node]['right'] = $links[$pivot]['left'];
        if ($links[$pivot]['left'] !== self::NOSTREAM) {
            $links[$links[$pivot]['left']]['parent'] = $node;
        }
        $links[$pivot]['parent'] = $links[$node]['parent'];
        if ($links[$node]['parent'] === self::NOSTREAM) {
            $root = $pivot;
        } elseif ($node === $links[$links[$node]['parent']]['left']) {
            $links[$links[$node]['parent']]['left'] = $pivot;
        } else {
            $links[$links[$node]['parent']]['right'] = $pivot;
        }
        $links[$pivot]['left'] = $node;
        $links[$node]['parent'] = $pivot;
    }

    private function rotateSiblingTreeRight(array &$links, int &$root, int $node): void {
        $pivot = $links[$node]['left'];
        if ($pivot === self::NOSTREAM) {
            throw new \RuntimeException('Internal CFB directory tree rotation error');
        }
        $links[$node]['left'] = $links[$pivot]['right'];
        if ($links[$pivot]['right'] !== self::NOSTREAM) {
            $links[$links[$pivot]['right']]['parent'] = $node;
        }
        $links[$pivot]['parent'] = $links[$node]['parent'];
        if ($links[$node]['parent'] === self::NOSTREAM) {
            $root = $pivot;
        } elseif ($node === $links[$links[$node]['parent']]['right']) {
            $links[$links[$node]['parent']]['right'] = $pivot;
        } else {
            $links[$links[$node]['parent']]['left'] = $pivot;
        }
        $links[$pivot]['right'] = $node;
        $links[$node]['parent'] = $pivot;
    }

    private function treeColor(array $links, int $node): int {
        return $node === self::NOSTREAM ? 1 : $links[$node]['color'];
    }

    private function collectDirectoryEntries(array $node, array &$entries): void {
        $entries[$node['id']] = $node;
        foreach ($node['children'] as $child) {
            $this->collectDirectoryEntries($child, $entries);
        }
    }

    private function encodeDirectoryEntry(array $entry): string {
        $name = $entry['name'] . "\x00\x00";
        if (strlen($name) > 64 || (strlen($name) & 1) !== 0) {
            throw new \RuntimeException('CFB directory name cannot be encoded');
        }
        $size = $entry['type'] === self::DIR_STORAGE ? 0 : ($entry['size'] ?? 0);
        $startSector = $entry['type'] === self::DIR_STORAGE
            ? 0
            : ($entry['startSector'] ?? self::ENDOFCHAIN);
        $encoded = str_pad($name, 64, "\x00")
            . pack('v', strlen($name))
            . chr($entry['type'])
            . chr($entry['color'])
            . pack('V', $entry['left'])
            . pack('V', $entry['right'])
            . pack('V', $entry['child'])
            . $entry['clsid']
            . $entry['stateBits']
            . $entry['creationTime']
            . $entry['modifiedTime']
            . pack('V', $startSector)
            . $this->packUInt64($size);
        if (strlen($encoded) !== 128) {
            throw new \RuntimeException('Internal CFB directory entry encoding error');
        }
        return $encoded;
    }

    private function newStream(string $name, string $data, ?array $template = null): array {
        if ($template !== null) {
            $template['name'] = $this->asciiToUtf16Le($name);
            $template['type'] = self::DIR_STREAM;
            $template['data'] = $data;
            $template['children'] = [];
            return $template;
        }
        return [
            'name' => $this->asciiToUtf16Le($name),
            'type' => self::DIR_STREAM,
            'clsid' => str_repeat("\x00", 16),
            'stateBits' => str_repeat("\x00", 4),
            'creationTime' => str_repeat("\x00", 8),
            'modifiedTime' => str_repeat("\x00", 8),
            'children' => [],
            'data' => $data,
        ];
    }

    private function hasCompleteDirectoryLayout(array $root): bool {
        $entries = [];
        if (!$this->collectExistingDirectoryLayout($root, $entries)) {
            return false;
        }
        if (count($entries) === 0 || min(array_keys($entries)) !== 0
            || max(array_keys($entries)) !== count($entries) - 1) {
            return false;
        }
        return true;
    }

    private function collectExistingDirectoryLayout(array $node, array &$entries): bool {
        foreach (['id', 'left', 'right', 'child', 'color'] as $field) {
            if (!array_key_exists($field, $node)) {
                return false;
            }
        }
        if (isset($entries[$node['id']])) {
            return false;
        }
        $entries[$node['id']] = true;
        foreach ($node['children'] as $child) {
            if (!$this->collectExistingDirectoryLayout($child, $entries)) {
                return false;
            }
        }
        return true;
    }

    private function isSignatureName(string $name): bool {
        return $name === $this->asciiToUtf16Le("\x05DigitalSignature")
            || $name === $this->asciiToUtf16Le("\x05MsiDigitalSignatureEx");
    }

    private function compareHashNames(string $left, string $right): int {
        $comparison = strcmp($left, $right);
        if ($comparison !== 0) {
            return $comparison;
        }
        return strlen($left) === strlen($right) ? 0 : (strlen($left) > strlen($right) ? -1 : 1);
    }

    private function compareTreeNames(string $left, string $right): int {
        if (strlen($left) !== strlen($right)) {
            return strlen($left) <=> strlen($right);
        }
        $left = $this->uppercaseUtf16Le($left);
        $right = $this->uppercaseUtf16Le($right);
        if (strlen($left) !== strlen($right)) {
            throw new \RuntimeException('CFB directory name has an unsupported uppercase mapping');
        }
        for ($offset = 0; $offset < strlen($left); $offset += 2) {
            $leftCodeUnit = $this->readUInt16($left, $offset, 'UTF-16 directory name');
            $rightCodeUnit = $this->readUInt16($right, $offset, 'UTF-16 directory name');
            if ($leftCodeUnit !== $rightCodeUnit) {
                return $leftCodeUnit <=> $rightCodeUnit;
            }
        }
        return 0;
    }

    private function validateChildNames(array $children): void {
        $sorted = $children;
        usort($sorted, fn(array $a, array $b): int => $this->compareTreeNames($a['name'], $b['name']));
        for ($i = 1; $i < count($sorted); $i++) {
            if ($this->compareTreeNames($sorted[$i - 1]['name'], $sorted[$i]['name']) === 0) {
                throw new \RuntimeException('Duplicate CFB directory entry name');
            }
        }
    }

    private function uppercaseUtf16Le(string $value): string {
        if (function_exists('mb_convert_encoding') && function_exists('mb_strtoupper')) {
            $utf8 = mb_convert_encoding($value, 'UTF-8', 'UTF-16LE');
            return mb_convert_encoding(mb_strtoupper($utf8, 'UTF-8'), 'UTF-16LE', 'UTF-8');
        }
        $result = '';
        for ($i = 0; $i < strlen($value); $i += 2) {
            $codepoint = $this->readUInt16($value, $i, 'UTF-16 directory name');
            if ($codepoint >= 0x61 && $codepoint <= 0x7A) {
                $codepoint -= 0x20;
            }
            $result .= pack('v', $codepoint);
        }
        return $result;
    }

    private function asciiToUtf16Le(string $value): string {
        $result = '';
        for ($i = 0; $i < strlen($value); $i++) {
            $result .= $value[$i] . "\x00";
        }
        return $result;
    }

    private function isMsiRootClsid(string $clsid): bool {
        $suffix = "\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46";
        return strlen($clsid) === 16
            && in_array(ord($clsid[0]), [0x82, 0x84, 0x86], true)
            && substr($clsid, 1) === $suffix;
    }

    private function readSector(string $data, int $sectorSize, int $sectorCount, int $sector): string {
        $this->assertRegularSector($sector, $sectorCount, 'sector');
        return substr($data, ($sector + 1) * $sectorSize, $sectorSize);
    }

    private function assertRegularSector(int $sector, int $sectorCount, string $context): void {
        if ($sector < 0 || $sector >= self::MAXREGSECT || $sector >= $sectorCount) {
            throw new \RuntimeException("Invalid CFB sector in {$context}");
        }
    }

    private function readUInt16(string $data, int $offset, string $context): int {
        if ($offset < 0 || $offset > strlen($data) - 2) {
            throw new \RuntimeException("Truncated CFB {$context}");
        }
        return unpack('v', substr($data, $offset, 2))[1];
    }

    private function readUInt32(string $data, int $offset, string $context): int {
        if ($offset < 0 || $offset > strlen($data) - 4) {
            throw new \RuntimeException("Truncated CFB {$context}");
        }
        return unpack('V', substr($data, $offset, 4))[1];
    }

    private function combineUInt64(int $low, int $high, string $context): int {
        if ($high > intdiv(PHP_INT_MAX - $low, 0x100000000)) {
            throw new \RuntimeException("CFB {$context} exceeds the supported size");
        }
        return $high * 0x100000000 + $low;
    }

    private function packUInt64(int $value): string {
        if ($value < 0) {
            throw new \RuntimeException('Cannot encode a negative CFB stream size');
        }
        return pack('V', $value & 0xFFFFFFFF) . pack('V', intdiv($value, 0x100000000));
    }

    private function writeFileSafely(string $path, string $contents, ?int $mode): void {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            throw new \RuntimeException("Output directory does not exist: {$directory}");
        }
        $temporary = tempnam($directory, '.foxy-sign-');
        if ($temporary === false) {
            throw new \RuntimeException("Unable to create temporary output beside: {$path}");
        }
        try {
            $written = @file_put_contents($temporary, $contents, LOCK_EX);
            if ($written !== strlen($contents)) {
                throw new \RuntimeException("Unable to write the complete MSI output: {$path}");
            }
            if ($mode !== null && !@chmod($temporary, $mode)) {
                throw new \RuntimeException("Unable to preserve MSI file mode for: {$path}");
            }
            if (@rename($temporary, $path)) {
                $temporary = '';
                return;
            }

            $backup = tempnam($directory, '.foxy-backup-');
            if ($backup === false || !@unlink($backup) || !@rename($path, $backup)) {
                throw new \RuntimeException("Unable to replace MSI output: {$path}");
            }
            try {
                if (!@rename($temporary, $path)) {
                    @rename($backup, $path);
                    throw new \RuntimeException("Unable to replace MSI output: {$path}");
                }
                $temporary = '';
                @unlink($backup);
            } catch (\Throwable $exception) {
                if (!file_exists($path)) {
                    @rename($backup, $path);
                }
                throw $exception;
            }
        } finally {
            if ($temporary !== '') {
                @unlink($temporary);
            }
        }
    }
}
