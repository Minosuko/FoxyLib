<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{DER, Hash, PEM};
use FoxySigningTool\PKCS7;

class MacOSSigner {
    private object $signerKey;
    private string $certDer;
    private string $hashAlgo;
    private array $extraCerts;

    const CSMAGIC_REQUIREMENT = 0xfade0c00;
    const CSMAGIC_REQUIREMENTS = 0xfade0c01;
    const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
    const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
    const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
    const CSSLOT_CODEDIRECTORY = 0x00000;
    const CSSLOT_INFOSLOT = 0x00001;
    const CSSLOT_REQUIREMENTS = 0x00002;
    const CSSLOT_RESOURCEDIR = 0x00003;
    const CSSLOT_APPLICATION = 0x00004;
    const CSSLOT_ENTITLEMENTS = 0x00005;
    const CSSLOT_SIGNATURE = 0x10000;

    public function __construct(object $signerKey, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []) {
        $this->signerKey = $signerKey;
        $this->certDer = PEM::decode($certPem)['data'];
        $this->hashAlgo = $hashAlgo;
        $this->extraCerts = $extraCerts;
    }

    public static function fromPKCS12(string $pkcs12Path, string $password, string $hashAlgo = 'sha256'): self {
        $pkcs12 = \FoxyCryptLib\FoxyCryptLib::pkcs12Decode(file_get_contents($pkcs12Path), $password);
        $keyInfo = $pkcs12['privateKeys'][0] ?? throw new \RuntimeException('No private key in PKCS12');
        $certDer = $pkcs12['certificates'][0] ?? throw new \RuntimeException('No certificate in PKCS12');
        $certPem = PEM::encode($certDer, 'CERTIFICATE');
        return new self(PESigner::keyInfoToKey($keyInfo), $certPem, $hashAlgo);
    }

    public static function fromPEM(string $keyPem, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []): self {
        $signerKey = PESigner::loadKeyFromPEM($keyPem);
        return new self($signerKey, $certPem, $hashAlgo, $extraCerts);
    }

    public function signFile(string $inputPath, ?string $outputPath = null): string {
        $data = file_get_contents($inputPath);
        $outputPath ??= $inputPath;

        $signed = $this->buildEmbeddedSignature($data);
        file_put_contents($outputPath, $signed);

        return $outputPath;
    }

    public function signDetached(string $data): string {
        $hash = hex2bin(Hash::hash($this->hashAlgo, $data));
        return PKCS7::buildDetachedSignature($hash, $this->signerKey, PEM::encode($this->certDer, 'CERTIFICATE'), $this->hashAlgo, $this->extraCerts);
    }

    public function buildEmbeddedSignature(string $machoData): string {
        $hash = hex2bin(Hash::hash($this->hashAlgo, $machoData));
        $pkcs7 = PKCS7::buildDetachedSignature($hash, $this->signerKey, PEM::encode($this->certDer, 'CERTIFICATE'), $this->hashAlgo, $this->extraCerts);

        $codeDir = $this->buildCodeDirectory($machoData);
        $reqBlob = $this->buildRequirementsBlob();

        $sigBlob = pack('N', self::CSMAGIC_EMBEDDED_SIGNATURE);
        $sigBlob .= pack('N', 0x20000);
        $sigBlob .= pack('N', 4);
        $sigBlob .= pack('N', self::CSSLOT_CODEDIRECTORY);
        $sigBlob .= pack('N', 0);
        $sigBlob .= pack('N', self::CSSLOT_REQUIREMENTS);
        $sigBlob .= pack('N', 0);
        $sigBlob .= pack('N', self::CSSLOT_SIGNATURE);
        $sigBlob .= pack('N', 0);
        $sigBlob .= pack('N', 0);
        $sigBlob .= pack('N', 0);

        $sigBlobOffset = strlen($sigBlob);
        $codeDirOffset = $sigBlobOffset;
        $sigBlob = substr_replace($sigBlob, pack('N', $codeDirOffset), 16 + 4 * 2, 4);
        $sigBlob .= $codeDir;

        $reqOffset = $sigBlobOffset + strlen($codeDir);
        $sigBlob = substr_replace($sigBlob, pack('N', $reqOffset), 16 + 4 * 4, 4);
        $sigBlob .= $reqBlob;

        $sigOffset = $sigBlobOffset + strlen($codeDir) + strlen($reqBlob);
        $sigBlob = substr_replace($sigBlob, pack('N', $sigOffset), 16 + 4 * 6, 4);
        $sigBlob .= $pkcs7;

        $pageSize = 4096;
        $pad = $pageSize - (strlen($machoData) % $pageSize);
        if ($pad !== $pageSize) {
            $machoData .= str_repeat("\x00", $pad);
        }

        return $machoData . $sigBlob;
    }

    private function buildCodeDirectory(string $data): string {
        $pageSize = 4096;
        $numPages = (int)ceil(strlen($data) / $pageSize);

        $cdHash = hex2bin(Hash::hash($this->hashAlgo, $data));

        $cd = pack('N', self::CSMAGIC_CODEDIRECTORY);
        $cd .= pack('N', 0); // version
        $cd .= pack('N', 0); // flags
        $cd .= pack('N', 0); // hashOffset
        $cd .= pack('N', 0); // identOffset
        $cd .= pack('N', 0); // nSpecialSlots
        $cd .= pack('N', $numPages + 1);
        $cd .= pack('N', $pageSize);
        $cd .= pack('N', 2);
        $cd .= pack('N', 0);
        $cd .= pack('N', 0);
        $cd .= pack('N', 0);
        $cd .= pack('N', 0);
        $cd .= pack('N', 0);
        $cd .= pack('N', 0);
        $cd .= pack('N', 8 * 4 + 4);

        $hashSize = match ($this->hashAlgo) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => 32,
        };

        $cd .= $cdHash;

        $ident = "com.foxy.signed\x00";
        $identOffset = strlen($cd);
        $cd = substr_replace($cd, pack('N', $identOffset), 16, 4);
        $cd .= $ident;

        $hashOffset = strlen($cd);
        $cd = substr_replace($cd, pack('N', $hashOffset), 8, 4);

        for ($i = 0; $i <= $numPages; $i++) {
            $pageStart = $i * $pageSize;
            $pageEnd = min(strlen($data), $pageStart + $pageSize);
            $pageData = substr($data, $pageStart, $pageEnd - $pageStart);
            $cd .= hex2bin(Hash::hash($this->hashAlgo, $pageData));
        }

        return $cd;
    }

    private function buildRequirementsBlob(): string {
        $reqData = pack('N', self::CSMAGIC_REQUIREMENT);
        $reqData .= pack('N', 0);
        $reqData .= pack('N', 0);

        $blob = pack('N', self::CSMAGIC_REQUIREMENTS);
        $blob .= pack('N', 12 + strlen($reqData));
        $blob .= $reqData;

        return $blob;
    }

    public function signDMG(string $inputPath, ?string $outputPath = null): string {
        return $this->signFile($inputPath, $outputPath);
    }

    public function signDylib(string $inputPath, ?string $outputPath = null): string {
        return $this->signFile($inputPath, $outputPath);
    }
}
