<?php
declare(strict_types=1);
namespace FoxySigningTool;

use FoxyCryptLib\{FoxyCryptLib, RSA, ECDSA, DSA, DER, PEM, Certificate\PKCS12};
use FoxySigningTool\Signer\{PESigner, ELFSigner, MacOSSigner, EFISigner, MSISigner, DocumentSigner};

class FoxySigningTool {
    // ---- Certificate Loading ----
    public static function loadKeyFromPEM(string $pem): object {
        return PESigner::loadKeyFromPEM($pem);
    }

    public static function loadPKCS12(string $path, string $password): array {
        return FoxyCryptLib::pkcs12Decode(file_get_contents($path), $password);
    }

    public static function extractCertFromPKCS12(array $pkcs12): array {
        $certs = [];
        foreach ($pkcs12['certificates'] ?? [] as $i => $der) {
            $certs[] = PEM::encode($der, 'CERTIFICATE');
        }
        return $certs;
    }

    public static function extractKeyFromPKCS12(array $pkcs12): object {
        $keyInfo = $pkcs12['privateKeys'][0] ?? throw new \RuntimeException('No private key found');
        return PESigner::keyInfoToKey($keyInfo);
    }

    // ---- File type detection ----
    public static function detectFileType(string $path): string {
        $fh = fopen($path, 'rb');
        $magic = fread($fh, 64);
        fclose($fh);

        if (substr($magic, 0, 2) === "MZ") {
            $peOffset = unpack('V', substr($magic, 0x3C, 4))[1] ?? 0;
            if ($peOffset > 0 && $peOffset < filesize($path)) {
                fclose(fopen($path, 'rb'));
                $fh = fopen($path, 'rb');
                fseek($fh, $peOffset);
                $peSig = fread($fh, 4);
                fclose($fh);
                if ($peSig === "PE\x00\x00") {
                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    if (in_array($ext, ['efi', 'rom', 'bin'])) return 'efi';
                    return 'pe';
                }
            }
        }

        if (substr($magic, 0, 4) === "\x7fELF") return 'elf';

        if (substr($magic, 0, 4) === "\xfa\xde\x0c\xc0" ||
            substr($magic, 1, 3) === "\xfa\xde\x0c" ||
            substr($magic, 0, 4) === "\xcf\xfa\xed\xfe" ||
            substr($magic, 0, 4) === "\xce\xfa\xed\xfe" ||
            substr($magic, 0, 4) === "\xfe\xed\xfa\xce" ||
            substr($magic, 0, 4) === "\xfe\xed\xfa\xcf") {
            return 'macho';
        }

        if (substr($magic, 0, 8) === "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (in_array($ext, ['msi', 'mst', 'msp'])) return 'msi';
            if (in_array($ext, ['doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx'])) return 'document';
            $name = basename($path);
            if (str_ends_with($name, '.msi') || stripos($name, '.msi') !== false) return 'msi';
            return 'document';
        }

        if (substr($magic, 0, 5) === "%PDF-") return 'document';

        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return match ($ext) {
            'exe', 'dll', 'ocx', 'sys', 'cpl', 'scr' => 'pe',
            'efi', 'rom', 'bin' => 'efi',
            'dmg', 'dylib', 'app', 'kext', 'bundle' => 'macho',
            'so', 'o', 'ko', 'a' => 'elf',
            'msi', 'mst', 'msp' => 'msi',
            'pdf' => 'document',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp' => 'document',
            default => 'unknown',
        };
    }

    // ---- High-level signing ----
    public static function sign(string $inputPath, object $signerKey, string $certPem, array $options = []): string {
        $type = self::detectFileType($inputPath);
        $hashAlgo = $options['hash'] ?? 'sha256';
        $outputPath = $options['output'] ?? $inputPath;
        $extraCerts = $options['extraCerts'] ?? [];

        return match ($type) {
            'pe' => (new PESigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signFile($inputPath, $outputPath),
            'efi' => (new EFISigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signFile($inputPath, $outputPath),
            'elf' => (new ELFSigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signFile($inputPath, $outputPath, $options['embedded'] ?? true),
            'macho' => (new MacOSSigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signFile($inputPath, $outputPath),
            'msi' => (new MSISigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signFile($inputPath, $outputPath),
            'document' => (new DocumentSigner($signerKey, $certPem, $hashAlgo, $extraCerts))->signDocument($inputPath, $outputPath, $options),
            default => throw new \RuntimeException("Unsupported file type: {$type}"),
        };
    }

    public static function signWithPKCS12(string $inputPath, string $pkcs12Path, string $password, array $options = []): string {
        $pkcs12 = self::loadPKCS12($pkcs12Path, $password);
        $key = self::extractKeyFromPKCS12($pkcs12);
        $certPems = self::extractCertFromPKCS12($pkcs12);
        $certPem = $certPems[0];
        $options['extraCerts'] = array_slice($certPems, 1);
        return self::sign($inputPath, $key, $certPem, $options);
    }

    public static function signWithPEM(string $inputPath, string $keyPem, string $certPem, array $options = []): string {
        $key = self::loadKeyFromPEM($keyPem);
        return self::sign($inputPath, $key, $certPem, $options);
    }

    // ---- Detached signature generation ----
    public static function signDetached(string $data, object $signerKey, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []): string {
        return PKCS7::buildDetachedSignature($data, $signerKey, $certPem, $hashAlgo, $extraCerts);
    }

    public static function getSupportedTypes(): array {
        return [
            'pe' => ['exe', 'dll', 'ocx', 'sys', 'cpl', 'scr'],
            'efi' => ['efi', 'rom'],
            'elf' => ['so', 'o', 'ko', 'a', 'linux binary'],
            'macho' => ['dmg', 'dylib', 'app', 'kext'],
            'msi' => ['msi', 'mst', 'msp'],
            'document' => ['pdf', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'],
        ];
    }
}
