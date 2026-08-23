<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{PEM, RSA, X509Certificate};

final class DocumentSigner {
    public const OID_ADBE_REVOCATION = '1.2.840.113583.1.1.8';
    public const OID_DOC_TIMESTAMP = '1.2.840.113583.1.1.9';

    private PDFSigner $pdfSigner;
    private PackageSigner $packageSigner;
    private ?array $timestamp;

    public function __construct(
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        ?array $timestamp = null
    ) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('Document signing requires an RSA private key');
        }
        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY'));
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('Document signing requires an RSA certificate', 0, $exception);
        }
        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('Document signing key does not match the certificate');
        }

        $this->pdfSigner = new PDFSigner($signerKey, $certPem, $hashAlgo, $extraCerts, $timestamp);
        $this->packageSigner = new PackageSigner($signerKey, $certPem, $hashAlgo, $extraCerts);
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
            throw new \RuntimeException('Document signing requires an RSA key in PKCS12');
        }
        $keyPublic = $signerKey->getPublicKey();
        $certDer = null;
        $extraCerts = [];
        foreach ($pkcs12['certificates'] ?? [] as $candidateDer) {
            $candidatePem = PEM::encode($candidateDer, 'CERTIFICATE');
            try {
                $candidate = X509Certificate::fromDER($candidateDer);
                $candidateKey = RSA::fromPEM(PEM::encode($candidate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY'));
                $candidatePublic = $candidateKey->getPublicKey();
                $matches = $keyPublic['n']->equals($candidatePublic['n'])
                    && $keyPublic['e']->equals($candidatePublic['e']);
            } catch (\Throwable) {
                $matches = false;
            }
            if ($certDer === null && $matches) {
                $certDer = $candidateDer;
            } else {
                $extraCerts[] = $candidatePem;
            }
        }
        if ($certDer === null) {
            throw new \RuntimeException('No certificate in PKCS12 matches the private key');
        }
        return new self(
            $signerKey,
            PEM::encode($certDer, 'CERTIFICATE'),
            $hashAlgo,
            $extraCerts
        );
    }

    public static function fromPEM(
        string $keyPem,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = []
    ): self {
        return new self(PESigner::loadKeyFromPEM($keyPem), $certPem, $hashAlgo, $extraCerts);
    }

    public function signPDF(string $inputPath, ?string $outputPath = null, array $options = []): string {
        return $this->pdfSigner->signFile($inputPath, $outputPath, $options);
    }

    public function signPDFBinary(string $pdfData, array $options = []): string {
        return $this->pdfSigner->signBinary($pdfData, $options);
    }

    public function signOffice(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signFile($inputPath, $outputPath, null, $options);
    }

    public function signOfficeBinary(string $officeData, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signBinary($officeData, null, $options);
    }

    public function signOOXML(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signFile($inputPath, $outputPath, 'ooxml', $options);
    }

    public function signOOXMLBinary(string $package, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signBinary($package, 'ooxml', $options);
    }

    public function signODF(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signFile($inputPath, $outputPath, 'odf', $options);
    }

    public function signODFBinary(string $package, array $options = []): string {
        $this->assertPackageTimestampNotRequested();
        return $this->packageSigner->signBinary($package, 'odf', $options);
    }

    public function signDocument(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $extension = strtolower(pathinfo($inputPath, PATHINFO_EXTENSION));
        return match ($extension) {
            'pdf' => $this->signPDF($inputPath, $outputPath, $options),
            'docx', 'xlsx', 'pptx' => $this->signOOXML($inputPath, $outputPath, $options),
            'odt', 'ods', 'odp' => $this->signODF($inputPath, $outputPath, $options),
            'doc', 'xls', 'ppt' => throw new \RuntimeException(
                'Legacy binary Office formats are not supported; convert the file to OOXML first'
            ),
            default => throw new \RuntimeException("Unsupported document format: .{$extension}"),
        };
    }

    private function assertPackageTimestampNotRequested(): void {
        if ($this->timestamp !== null) {
            throw new \RuntimeException('RFC 3161 timestamps are not supported for OOXML or ODF XML signatures');
        }
    }
}
