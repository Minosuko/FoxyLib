<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{DER, Hash, PEM};
use FoxySigningTool\PKCS7;

class PESigner {
    private object $signerKey;
    private string $certDer;
    private string $hashAlgo;
    private array $extraCerts;
    private ?array $timestamp;

    public function __construct(object $signerKey, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = [], ?array $timestamp = null) {
        $this->signerKey = $signerKey;
        $this->certDer = PEM::decode($certPem)['data'];
        $this->hashAlgo = $hashAlgo;
        $this->extraCerts = $extraCerts;
        $this->timestamp = $timestamp;
    }

    public static function fromPKCS12(string $pkcs12Path, string $password, string $hashAlgo = 'sha256'): self {
        $pkcs12 = \FoxyCryptLib\FoxyCryptLib::pkcs12Decode(file_get_contents($pkcs12Path), $password);
        $keyInfo = $pkcs12['privateKeys'][0] ?? throw new \RuntimeException('No private key in PKCS12');
        $certDer = $pkcs12['certificates'][0] ?? throw new \RuntimeException('No certificate in PKCS12');
        $certPem = PEM::encode($certDer, 'CERTIFICATE');
        $extraCerts = array_slice($pkcs12['certificates'], 1);

        $signerKey = self::keyInfoToKey($keyInfo);

        $self = new self($signerKey, $certPem, $hashAlgo);
        $self->extraCerts = array_map(fn($c) => PEM::encode($c, 'CERTIFICATE'), $extraCerts);
        return $self;
    }

    public static function fromPEM(string $keyPem, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []): self {
        $signerKey = self::loadKeyFromPEM($keyPem);
        return new self($signerKey, $certPem, $hashAlgo, $extraCerts);
    }

    public static function loadKeyFromPEM(string $pem): object {
        if (str_contains($pem, 'EC PRIVATE KEY') || (str_contains($pem, 'PRIVATE KEY') && !str_contains($pem, 'RSA') && !str_contains($pem, 'DSA'))) {
            return \FoxyCryptLib\ECDSA::fromPEM($pem);
        }
        if (str_contains($pem, 'RSA PRIVATE KEY') || (str_contains($pem, 'PRIVATE KEY') && !str_contains($pem, 'DSA'))) {
            return \FoxyCryptLib\RSA::fromPEM($pem);
        }
        if (str_contains($pem, 'DSA PRIVATE KEY')) {
            return \FoxyCryptLib\DSA::fromPEM($pem);
        }
        throw new \RuntimeException('Cannot determine key type from PEM');
    }

    public static function keyInfoToKey(array $keyInfo): object {
        $algo = $keyInfo['algorithm'] ?? '';
        $pkcs8 = $keyInfo['pkcs8'] ?? '';
        if ($algo === '1.2.840.113549.1.1.1') {
            $parsed = DER::parse($pkcs8);
            $innerKey = DER::parse($parsed['children'][2]['data']);
            $c = $innerKey['children'];
            return \FoxyCryptLib\RSA::fromPrivateKey(
                \FoxyCryptLib\BigInt::fromBytes($c[1]['data']),
                \FoxyCryptLib\BigInt::fromBytes($c[2]['data']),
                \FoxyCryptLib\BigInt::fromBytes($c[3]['data']),
                \FoxyCryptLib\BigInt::fromBytes($c[4]['data']),
                \FoxyCryptLib\BigInt::fromBytes($c[5]['data'])
            );
        }
        if ($algo === '1.2.840.10045.2.1') {
            return \FoxyCryptLib\ECDSA::fromPEM(PEM::encode($pkcs8, 'PRIVATE KEY'));
        }
        throw new \RuntimeException("Unsupported key algorithm: $algo");
    }

    public function signFile(string $inputPath, ?string $outputPath = null): string {
        $peData = file_get_contents($inputPath);
        $outputPath ??= $inputPath;

        // Pass 1: compute a dummy PKCS7 to determine exact cert table size
        $dummyHash = str_repeat("\x00", 32);
        $dummyPkcs7 = PKCS7::buildAuthenticodeSignature($dummyHash, $this->signerKey, PEM::encode($this->certDer, 'CERTIFICATE'), $this->hashAlgo, $this->extraCerts);
        $pkcs7Len = strlen($dummyPkcs7);

        // Extend file and place cert table at the aligned end
        $totalCertSize = 8 + $pkcs7Len; // WIN_CERTIFICATE header + PKCS7
        $alignedTotalCert = (($totalCertSize + 7) & ~7);
        $alignedFileEnd = ((strlen($peData) + 7) & ~7);
        $extended = $peData . str_repeat("\x00", $alignedFileEnd - strlen($peData)) . str_repeat("\x00", $alignedTotalCert);

        // Update security data directory entry
        $pe = $this->parsePE($extended);
        $secDirOff = $pe['securityDirDataDirOffset'];
        $extended = substr_replace($extended, pack('VV', $alignedFileEnd, $alignedTotalCert), $secDirOff, 8);

        // Authenticode omits the checksum, certificate directory, and
        // certificate table from the digest stream rather than zero-filling them.
        $pe2 = $this->parsePE($extended);
        $certOffset = $pe2['certTableOffset'];
        $certSize = $pe2['certTableSize'];
        $checksumOffset = $pe2['checksumOffset'];
        $secDirOff = $pe2['securityDirDataDirOffset'];
        if ($checksumOffset <= 0 || $secDirOff < $checksumOffset + 4
            || $certOffset < $secDirOff + 8 || $certOffset + $certSize > strlen($extended)) {
            throw new \RuntimeException('Invalid PE certificate table layout');
        }

        $hashData = substr($extended, 0, $checksumOffset)
            . substr($extended, $checksumOffset + 4, $secDirOff - ($checksumOffset + 4))
            . substr($extended, $secDirOff + 8, $certOffset - ($secDirOff + 8))
            . substr($extended, $certOffset + $certSize);

        $peHash = hex2bin(Hash::hash($this->hashAlgo, $hashData));

        // Pass 2: build PKCS7 with correct hash
        $timestamp = $this->timestamp;
        if ($timestamp !== null) {
            $timestamp['attributeOid'] = \FoxySigningTool\TimestampClient::OID_AUTHENTICODE_TIMESTAMP;
        }
        $pkcs7 = PKCS7::buildAuthenticodeSignature($peHash, $this->signerKey, PEM::encode($this->certDer, 'CERTIFICATE'), $this->hashAlgo, $this->extraCerts, '', $timestamp);

        // The timestamp token changes the certificate-table size, but that table and
        // its directory entry are excluded from the Authenticode digest.
        $totalCertSize = 8 + strlen($pkcs7);
        $alignedTotalCert = (($totalCertSize + 7) & ~7);
        if ($alignedTotalCert !== $certSize) {
            $extended = substr($extended, 0, $certOffset)
                . str_repeat("\x00", $alignedTotalCert)
                . substr($extended, $certOffset + $certSize);
            $extended = substr_replace($extended, pack('VV', $certOffset, $alignedTotalCert), $secDirOff, 8);
            $certSize = $alignedTotalCert;
        }

        // Embed: replace placeholder zeros with actual signature
        $winCert = pack('V', $totalCertSize) .
                   pack('v', 0x0200) .
                   pack('v', 0x0002) .
                   $pkcs7;
        $winCert .= str_repeat("\x00", $alignedTotalCert - $totalCertSize);

        $signed = substr_replace($extended, $winCert, $certOffset, $certSize);

        // Compute and update PE checksum (required for Authenticode on Windows 10+)
        $chkOff = $pe2['checksumOffset'];
        if ($chkOff > 0) {
            $sum = 0;
            $dataForChk = substr_replace($signed, "\x00\x00\x00\x00", $chkOff, 4);
            $len = strlen($dataForChk);
            for ($i = 0; $i < $len - 1; $i += 2) {
                $word = unpack('v', $dataForChk, $i)[1];
                $sum = ($sum & 0xFFFF) + ($sum >> 16) + $word;
                $sum = ($sum >> 16) + ($sum & 0xFFFF);
            }
            if ($len & 1) {
                $sum += ord($dataForChk[$len - 1]);
                $sum = ($sum >> 16) + ($sum & 0xFFFF);
            }
            $sum += $len;
            $sum = ($sum >> 16) + ($sum & 0xFFFF);
            $signed = substr_replace($signed, pack('V', $sum), $chkOff, 4);
        }

        file_put_contents($outputPath, $signed);

        return $outputPath;
    }

    public function signBinary(string $peBinary): string {
        // For binary signing, we need the full file context.
        // This method is kept for API compatibility but prefer signFile().
        $tempPath = tempnam(sys_get_temp_dir(), 'pe');
        file_put_contents($tempPath, $peBinary);
        $resultPath = $this->signFile($tempPath);
        $result = file_get_contents($resultPath);
        unlink($resultPath);
        return $result;
    }

    private function parsePE(string $data): array {
        $offset = 0;
        $magic = substr($data, 0, 2);
        if ($magic !== "MZ") throw new \RuntimeException('Not a PE file');

        $peOffset = unpack('V', substr($data, 0x3C, 4))[1];
        if (substr($data, $peOffset, 4) !== "PE\x00\x00") throw new \RuntimeException('Invalid PE signature');

        $coff = $peOffset + 4;
        $machine = unpack('v', substr($data, $coff, 2))[1];
        $numSections = unpack('v', substr($data, $coff + 2, 2))[1];
        $optHeaderSize = unpack('v', substr($data, $coff + 16, 2))[1];

        $optOffset = $coff + 20;
        $magicPE = substr($data, $optOffset, 2);
        $isPE32Plus = ($magicPE === "\x0B\x02");

        if ($isPE32Plus) {
            $checksumOffset = $optOffset + 64;
            $dataDirOffset = $optOffset + 112;
            $dataDirCount = 16;
        } else {
            $checksumOffset = $optOffset + 64;
            $dataDirOffset = $optOffset + 96;
            $dataDirCount = 16;
        }

        $securityDir = substr($data, $dataDirOffset + 4 * 8, 8);
        $secDirVA = unpack('V', substr($securityDir, 0, 4))[1];
        $secDirSize = unpack('V', substr($securityDir, 4, 4))[1];

        $certTableOffset = $secDirVA;
        // Note: the security directory "RVA" field is actually a file offset — do NOT map through sections

        return [
            'peOffset' => $peOffset,
            'checksumOffset' => $checksumOffset,
            'certTableOffset' => $certTableOffset,
            'certTableSize' => $secDirSize,
            'securityDirDataDirOffset' => $dataDirOffset + 4 * 8,
            'optionalHeader' => [
                'dataDirectories' => [
                    4 => ['virtualAddress' => $secDirVA, 'size' => $secDirSize]
                ]
            ]
        ];
    }

    private function vaToOffset(string $data, int $va, int $peOffset, int $optOffset, int $optHeaderSize): int {
        $numSections = unpack('v', substr($data, $peOffset + 6, 2))[1];
        $sectionOffset = $optOffset + $optHeaderSize;

        for ($i = 0; $i < $numSections; $i++) {
            $sect = substr($data, $sectionOffset + $i * 40, 40);
            $sectVA = unpack('V', substr($sect, 12, 4))[1];
            $sectSize = unpack('V', substr($sect, 8, 4))[1];
            $sectRawOffset = unpack('V', substr($sect, 20, 4))[1];
            $sectRawSize = unpack('V', substr($sect, 16, 4))[1];

            if ($va >= $sectVA && $va < $sectVA + $sectSize) {
                $delta = $va - $sectVA;
                if ($delta < $sectRawSize) {
                    return $sectRawOffset + $delta;
                }
                return $sectRawOffset + $sectRawSize;
            }
        }
        return $va;
    }


}
