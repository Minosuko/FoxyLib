<?php
declare(strict_types=1);

require dirname(__DIR__) . '/../FoxyCryptLib/autoload.php';
require dirname(__DIR__) . '/autoload.php';

use FoxyCryptLib\DER;
use FoxyCryptLib\Hash;
use FoxyCryptLib\PEM;
use FoxyCryptLib\RSA;
use FoxyCryptLib\X509Certificate;
use FoxySigningTool\FoxySigningTool;

function apkExpect(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function apkUInt32(string $data, int $offset): int {
    return unpack('Vvalue', substr($data, $offset, 4))['value'];
}

function apkUInt64(string $data, int $offset): int {
    $parts = unpack('Vlow/Vhigh', substr($data, $offset, 8));
    apkExpect($parts['high'] === 0, 'APK test encountered an unsupported 64-bit size');
    return $parts['low'];
}

function apkEocdOffset(string $apk): int {
    $length = strlen($apk);
    $minimum = max(0, $length - 22 - 0xffff);
    for ($offset = $length - 22; $offset >= $minimum; $offset--) {
        if (substr($apk, $offset, 4) !== "PK\x05\x06") {
            continue;
        }
        $commentLength = unpack('vvalue', substr($apk, $offset + 20, 2))['value'];
        if ($offset + 22 + $commentLength === $length) {
            return $offset;
        }
    }
    throw new RuntimeException('Signed APK has no EOCD record');
}

function apkSigningBlockIds(string $apk): array {
    $eocdOffset = apkEocdOffset($apk);
    $centralDirectoryOffset = apkUInt32($apk, $eocdOffset + 16);
    apkExpect(
        substr($apk, $centralDirectoryOffset - 16, 16) === 'APK Sig Block 42',
        'APK Signing Block magic is missing'
    );
    $size = apkUInt64($apk, $centralDirectoryOffset - 24);
    $blockOffset = $centralDirectoryOffset - $size - 8;
    apkExpect(apkUInt64($apk, $blockOffset) === $size, 'APK Signing Block sizes differ');
    apkExpect($blockOffset % 4096 === 0, 'APK Signing Block start is not page aligned');
    apkExpect(
        ($centralDirectoryOffset - $blockOffset) % 4096 === 0,
        'APK Signing Block is not 4096-byte aligned in size'
    );

    $ids = [];
    $cursor = $blockOffset + 8;
    $end = $centralDirectoryOffset - 24;
    while ($cursor < $end) {
        $pairLength = apkUInt64($apk, $cursor);
        apkExpect($pairLength >= 4 && $cursor + 8 + $pairLength <= $end, 'APK signing pair is malformed');
        $ids[] = apkUInt32($apk, $cursor + 8);
        $cursor += 8 + $pairLength;
    }
    apkExpect($cursor === $end, 'APK signing pairs do not end at the block footer');
    return $ids;
}

function apkEntryDataOffset(string $apk, string $wantedName): int {
    $eocdOffset = apkEocdOffset($apk);
    $offset = apkUInt32($apk, $eocdOffset + 16);
    $entryCount = unpack('vvalue', substr($apk, $eocdOffset + 10, 2))['value'];
    for ($index = 0; $index < $entryCount; $index++) {
        apkExpect(substr($apk, $offset, 4) === "PK\x01\x02", 'Malformed test Central Directory');
        $nameLength = unpack('vvalue', substr($apk, $offset + 28, 2))['value'];
        $extraLength = unpack('vvalue', substr($apk, $offset + 30, 2))['value'];
        $commentLength = unpack('vvalue', substr($apk, $offset + 32, 2))['value'];
        $name = substr($apk, $offset + 46, $nameLength);
        if ($name === $wantedName) {
            $localOffset = apkUInt32($apk, $offset + 42);
            apkExpect(substr($apk, $localOffset, 4) === "PK\x03\x04", 'Malformed test local record');
            $localNameLength = unpack('vvalue', substr($apk, $localOffset + 26, 2))['value'];
            $localExtraLength = unpack('vvalue', substr($apk, $localOffset + 28, 2))['value'];
            return $localOffset + 30 + $localNameLength + $localExtraLength;
        }
        $offset += 46 + $nameLength + $extraLength + $commentLength;
    }
    throw new RuntimeException("APK test entry not found: {$wantedName}");
}

function apkV1CertificatePem(X509Certificate $certificate, RSA $key): string {
    $parsed = DER::parse($certificate->getDER());
    $tbsChildren = $parsed['children'][0]['children'];
    if (($tbsChildren[0]['tag'] ?? null) === 0xa0) {
        array_shift($tbsChildren);
    }
    if (($tbsChildren[array_key_last($tbsChildren)]['tag'] ?? null) === 0xa3) {
        array_pop($tbsChildren);
    }
    $tbs = DER::encodeSequence(array_map(
        static fn(array $element): string => $element['raw'],
        $tbsChildren
    ));
    $digest = hex2bin(Hash::hash('sha256', $tbs));
    apkExpect(is_string($digest), 'Unable to create X.509 v1 test certificate digest');
    $der = DER::encodeSequence([
        $tbs,
        $parsed['children'][1]['raw'],
        DER::encodeBitString($key->sign($digest, 'sha256')),
    ]);
    return PEM::encode($der, 'CERTIFICATE');
}

if (!class_exists(ZipArchive::class)) {
    throw new RuntimeException('APK smoke tests require the PHP zip extension');
}

$base = tempnam(sys_get_temp_dir(), 'foxy-apk-test-');
if ($base === false) {
    throw new RuntimeException('Unable to allocate APK smoke-test paths');
}
@unlink($base);
$input = $base . '.apk';
$requestedOutput = $argv[1] ?? getenv('FOXY_APK_TEST_OUTPUT');
$output = is_string($requestedOutput) && $requestedOutput !== ''
    ? $requestedOutput
    : $base . '-signed.apk';
$keepOutput = $output === $requestedOutput && $requestedOutput !== '';
$directoryOutput = $base . '-directory';

try {
    $zip = new ZipArchive();
    apkExpect(
        $zip->open($input, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true,
        'Unable to create APK smoke-test fixture'
    );
    $zip->addFromString('AndroidManifest.xml', '<manifest package="test.foxy"/>');
    $zip->addFromString('classes.dex', "dex\n035\x00synthetic");
    $zip->addFromString('123', 'numeric entry name');
    $chunkContents = str_repeat("\x5a", 1048577);
    apkExpect(Hash::hash('sha1', $chunkContents) === hash('sha1', $chunkContents), 'SHA-1 chunk digest mismatch');
    apkExpect(Hash::hash('sha256', $chunkContents) === hash('sha256', $chunkContents), 'SHA-256 chunk digest mismatch');
    $zip->addFromString('assets/chunk.bin', $chunkContents);
    $zip->setCompressionName('assets/chunk.bin', ZipArchive::CM_STORE);
    $zip->addFromString('lib/arm64-v8a/libtest.so', str_repeat("\x7fELF", 32));
    $zip->setCompressionName('lib/arm64-v8a/libtest.so', ZipArchive::CM_STORE);
    $zip->addFromString(
        'META-INF/MANIFEST.MF',
        "Manifest-Version: 1.0\r\nCreated-By: APK smoke fixture\r\n\r\n"
    );
    $zip->addFromString('META-INF/OLD.SF', 'obsolete');
    $zip->addFromString('META-INF/OLD.RSA', 'obsolete');
    $zip->addFromString('stamp-cert-sha256', str_repeat('x', 32));
    apkExpect($zip->close(), 'Unable to finalize APK smoke-test fixture');
    $unsigned = file_get_contents($input);
    apkExpect(is_string($unsigned), 'Unable to read unsigned APK smoke-test fixture');
    $nativeDataOffset = apkEntryDataOffset($unsigned, 'lib/arm64-v8a/libtest.so');

    $key = (new RSA(2048))->generateKeys();
    $certificate = X509Certificate::createSelfSigned($key, ['CN' => 'Foxy APK Test']);
    apkExpect(
        isset(X509Certificate::fromPEM($certificate->getPEM())['subjectPublicKeyInfo']),
        'X.509 v3 test certificate was not parsed'
    );
    $certificatePem = apkV1CertificatePem($certificate, $key);

    apkExpect(mkdir($directoryOutput), 'Unable to create APK directory-output test fixture');
    $directoryRejected = false;
    try {
        FoxySigningTool::sign($input, $key, $certificatePem, ['output' => $directoryOutput]);
    } catch (RuntimeException) {
        $directoryRejected = true;
    }
    apkExpect($directoryRejected, 'APK signing accepted a directory as its output path');
    apkExpect(is_dir($directoryOutput), 'APK signing moved or replaced its directory output path');

    apkExpect(FoxySigningTool::detectFileType($input) === 'apk', 'APK file type was not detected');
    apkExpect(
        (FoxySigningTool::getSupportedTypes()['apk'] ?? null) === ['apk'],
        'APK is absent from supported file types'
    );
    apkExpect(
        FoxySigningTool::sign($input, $key, $certificatePem, [
            'output' => $output,
            'apkMinSdk' => 17,
        ]) === $output,
        'High-level APK signing returned the wrong output path'
    );
    $firstSignedSize = filesize($output);
    apkExpect(is_int($firstSignedSize), 'Unable to inspect first signed APK size');

    // Re-sign in place to exercise replacement of an existing v1/v2/v3 signature set.
    FoxySigningTool::sign($output, $key, $certificatePem, ['apkMinSdk' => 17]);
    $secondSignedSize = filesize($output);
    apkExpect(
        is_int($secondSignedSize) && $secondSignedSize <= $firstSignedSize + 64,
        'Re-signing accumulated stale local signature records'
    );
    $signed = file_get_contents($output);
    apkExpect($signed !== false, 'Unable to read signed APK smoke-test output');
    $ids = apkSigningBlockIds($signed);
    apkExpect(in_array(0x7109871a, $ids, true), 'APK v2 signing block is missing');
    apkExpect(in_array(0xf05368c0, $ids, true), 'APK v3 signing block is missing');
    apkExpect(in_array(0x42726577, $ids, true), 'APK signing-block padding pair is missing');
    apkExpect(
        apkEntryDataOffset($signed, 'lib/arm64-v8a/libtest.so') === $nativeDataOffset,
        'APK signing changed an existing local entry offset'
    );

    $zip = new ZipArchive();
    apkExpect($zip->open($output, ZipArchive::CHECKCONS) === true, 'Signed APK is not a valid ZIP archive');
    apkExpect($zip->locateName('META-INF/OLD.SF') === false, 'Old APK .SF entry was retained');
    apkExpect($zip->locateName('META-INF/OLD.RSA') === false, 'Old APK .RSA entry was retained');
    apkExpect($zip->locateName('stamp-cert-sha256') === false, 'Old APK SourceStamp marker was retained');
    apkExpect($zip->locateName('123') !== false, 'Numeric APK entry name was not retained');
    apkExpect($zip->locateName('META-INF/FOXY.SF') !== false, 'New APK .SF entry is missing');
    apkExpect($zip->locateName('META-INF/FOXY.RSA') !== false, 'New APK .RSA entry is missing');
    $manifest = $zip->getFromName('META-INF/MANIFEST.MF');
    $signatureFile = $zip->getFromName('META-INF/FOXY.SF');
    apkExpect(is_string($manifest) && str_contains($manifest, 'Created-By: APK smoke fixture'), 'Manifest main attributes were not preserved');
    apkExpect(is_string($manifest) && str_contains($manifest, 'SHA1-Digest:'), 'Legacy APK v1 SHA-1 digests are missing');
    apkExpect(is_string($signatureFile) && str_contains($signatureFile, 'X-Android-APK-Signed: 2, 3'), 'APK v1 stripping protection is missing');
    apkExpect($zip->close(), 'Unable to close signed APK smoke-test output');

    echo "FoxySigningTool APK v1/v2/v3 smoke tests passed\n";
    if ($keepOutput) {
        echo "Signed APK fixture: {$output}\n";
    }
} finally {
    @unlink($input);
    if (!$keepOutput) {
        @unlink($output);
    }
    @rmdir($directoryOutput);
}
