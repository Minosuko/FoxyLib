<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\PEM;

class EFISigner {
    private object $signerKey;
    private string $certDer;
    private string $hashAlgo;
    private array $extraCerts;

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
        return $this->peSigner()->signFile($inputPath, $outputPath);
    }

    public function signBinary(string $efiData): string {
        return $this->peSigner()->signBinary($efiData);
    }

    private function peSigner(): PESigner {
        return new PESigner(
            $this->signerKey,
            PEM::encode($this->certDer, 'CERTIFICATE'),
            $this->hashAlgo,
            $this->extraCerts
        );
    }

    public function authenticate(string $inputPath, ?string $outputPath = null): string {
        return $this->signFile($inputPath, $outputPath);
    }
}
