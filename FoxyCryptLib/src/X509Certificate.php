<?php
declare(strict_types=1);
namespace FoxyCryptLib;

use FoxyCryptLib\Certificate\Extension;

class X509Certificate {
    private array $subject;
    private array $issuer;
    private BigInt $serialNumber;
    private int $validFrom;
    private int $validTo;
    private object $subjectKey;
    private ?object $issuerKey;
    private string $issuerKeyType = 'rsa';
    private ?string $signatureAlgo;
    private string $keyType = 'rsa';
    private string $der = '';
    private ?string $issuerUniqueId = null;
    private ?string $subjectUniqueId = null;
    private string $tbsDer = '';
    private string $savedSignature = '';
    private array $extensions = [];

    public function __construct() {
        $this->serialNumber = BigInt::fromInt(random_int(1, PHP_INT_MAX));
        $this->validFrom = time();
        $this->validTo = time() + 365 * 86400;
        $this->signatureAlgo = 'sha256';
        $this->subject = [];
        $this->issuer = [];
    }

    public function setSubject(array $subject): self { $this->subject = $subject; return $this; }
    public function setIssuer(array $issuer): self { $this->issuer = $issuer; return $this; }
    public function setSerialNumber(BigInt $sn): self { $this->serialNumber = $sn; return $this; }
    public function setValidity(int $from, int $to): self { $this->validFrom = $from; $this->validTo = $to; return $this; }
    public function setSignatureAlgorithm(string $algo): self { $this->signatureAlgo = $algo; return $this; }

    public function setSubjectPublicKey(RSA $rsa): self {
        $this->subjectKey = $rsa; $this->keyType = 'rsa'; return $this;
    }

    public function setIssuerPrivateKey(RSA $rsa): self {
        $this->issuerKey = $rsa; $this->issuerKeyType = 'rsa'; return $this;
    }

    public function setSubjectPublicKeyEC(ECDSA $ec): self {
        $this->subjectKey = $ec; $this->keyType = 'ec'; return $this;
    }

    public function setIssuerPrivateKeyEC(ECDSA $ec): self {
        $this->issuerKey = $ec; $this->issuerKeyType = 'ec'; return $this;
    }

    public function setIssuerPrivateKeyFromRSAOrEC(RSA|ECDSA $key): self {
        if ($key instanceof ECDSA) {
            return $this->setIssuerPrivateKeyEC($key);
        }
        return $this->setIssuerPrivateKey($key);
    }

    public function setSubjectPublicKeyFromRSAOrEC(RSA|ECDSA $key): self {
        if ($key instanceof ECDSA) {
            return $this->setSubjectPublicKeyEC($key);
        }
        return $this->setSubjectPublicKey($key);
    }

    public function addExtension(Extension $ext): self {
        $this->extensions[] = $ext; return $this;
    }

    public function setExtensions(array $exts): self {
        $this->extensions = $exts; return $this;
    }

    public function getExtensions(): array { return $this->extensions; }
    public function getSubject(): array { return $this->subject; }
    public function getSubjectKey(): RSA|ECDSA { return $this->subjectKey; }
    public function getKeyType(): string { return $this->keyType; }

    public function computeSubjectKeyIdentifier(): string {
        return self::keyIdentifier($this->subjectKey);
    }

    public static function encodeSPKI(RSA|ECDSA $key): string {
        if ($key instanceof ECDSA) {
            $curve = $key->getCurve();
            $pk = $key->getPublicKey();
            $point = ECC::encodePoint($pk['x'], $pk['y'], $curve->keySize);
            return DER::encodeSequence([
                DER::encodeSequence([
                    DER::encodeOID('1.2.840.10045.2.1'),
                    DER::encodeOID($curve->oid)
                ]),
                DER::encodeBitString($point)
            ]);
        }
        $pk = $key->getPublicKey();
        $keyDer = DER::encodeSequence([
            DER::encodeInteger($pk['n']->toBytes()),
            DER::encodeInteger($pk['e']->toBytes())
        ]);
        return DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID('1.2.840.113549.1.1.1'),
                DER::encodeNull()
            ]),
            DER::encodeBitString($keyDer)
        ]);
    }

    public static function keyIdentifier(RSA|ECDSA $key): string {
        return hex2bin(Hash::hash('sha1', self::encodeSPKI($key)));
    }

    private function encodeName(array $name): string {
        $rdns = [];
        $oidMap = [
            'CN' => '2.5.4.3', 'commonName' => '2.5.4.3',
            'O' => '2.5.4.10', 'organizationName' => '2.5.4.10', 'organization' => '2.5.4.10',
            'OU' => '2.5.4.11', 'organizationalUnitName' => '2.5.4.11',
            'L' => '2.5.4.7', 'localityName' => '2.5.4.7',
            'ST' => '2.5.4.8', 'stateOrProvinceName' => '2.5.4.8',
            'C' => '2.5.4.6', 'countryName' => '2.5.4.6',
            'STREET' => '2.5.4.9', 'streetAddress' => '2.5.4.9',
            'E' => '1.2.840.113549.1.9.1', 'emailAddress' => '1.2.840.113549.1.9.1',
            'UID' => '0.9.2342.19200300.100.1.1',
            'DC' => '0.9.2342.19200300.100.1.25', 'domainComponent' => '0.9.2342.19200300.100.1.25',
            'SERIALNUMBER' => '2.5.4.5', 'serialNumber' => '2.5.4.5',
        ];
        foreach ($name as $key => $value) {
            $oid = $oidMap[$key] ?? $key;
            $isPrintable = preg_match('/^[A-Za-z0-9 \'\(\)\+\,\-\.\/\:\=\?]+$/', $value) === 1;
            $strEnc = $isPrintable ? DER::encodePrintableString($value) : DER::encodeUTF8String($value);
            $rdns[] = DER::encodeSet([DER::encodeSequence([DER::encodeOID($oid), $strEnc])]);
        }
        return DER::encodeSequence($rdns);
    }

    private function encodeValidity(): string {
        return DER::encodeSequence([
            DER::encodeTime((new \DateTimeImmutable())->setTimestamp($this->validFrom), true),
            DER::encodeTime((new \DateTimeImmutable())->setTimestamp($this->validTo), false)
        ]);
    }

    private function encodeSubjectPublicKeyInfo(): string {
        return self::encodeSPKI($this->subjectKey);
    }

    private function encodeTBSCertificate(): string {
        $tbsParts = [
            DER::encodeContextSpecific(0, DER::encodeInteger("\x02")),
            DER::encodeInteger($this->serialNumber->toBytes()),
            DER::encodeSequence([
                DER::encodeOID($this->getSignatureOID()),
                DER::encodeNull()
            ]),
            $this->encodeName($this->issuer),
            $this->encodeValidity(),
            $this->encodeName($this->subject),
            $this->encodeSubjectPublicKeyInfo(),
        ];

        if ($this->issuerUniqueId) {
            $tbsParts[] = DER::encodeContextSpecific(1, DER::encodeBitString($this->issuerUniqueId));
        }
        if ($this->subjectUniqueId) {
            $tbsParts[] = DER::encodeContextSpecific(2, DER::encodeBitString($this->subjectUniqueId));
        }

        $extChildren = [];
        foreach ($this->extensions as $ext) {
            $extChildren[] = $ext->encode();
        }
        if ($extChildren) {
            $tbsParts[] = DER::encodeContextSpecific(3, DER::encodeSequence($extChildren));
        }

        return DER::encodeSequence($tbsParts);
    }

    private function getSignatureOID(): string {
        if ($this->issuerKeyType === 'ec') {
            $map = [
                'sha256' => '1.2.840.10045.4.3.2',
                'sha384' => '1.2.840.10045.4.3.3',
                'sha512' => '1.2.840.10045.4.3.4',
            ];
            return $map[$this->signatureAlgo] ?? '1.2.840.10045.4.3.2';
        }
        $map = [
            'md5' => '1.2.840.113549.1.1.4',
            'sha1' => '1.2.840.113549.1.1.5',
            'sha224' => '1.2.840.113549.1.1.14',
            'sha256' => '1.2.840.113549.1.1.11',
            'sha384' => '1.2.840.113549.1.1.12',
            'sha512' => '1.2.840.113549.1.1.13',
        ];
        return $map[$this->signatureAlgo] ?? '1.2.840.113549.1.1.11';
    }

    public function sign(): string {
        if (!$this->issuerKey) throw new \RuntimeException('Issuer private key required');
        $this->tbsDer = $this->encodeTBSCertificate();
        $digest = hex2bin(Hash::hash($this->signatureAlgo, $this->tbsDer));

        if ($this->issuerKeyType === 'ec') {
            $this->savedSignature = $this->issuerKey->sign($this->tbsDer);
        } else {
            $this->savedSignature = $this->issuerKey->sign($digest, $this->signatureAlgo);
        }

        $this->der = DER::encodeSequence([
            $this->tbsDer,
            DER::encodeSequence([
                DER::encodeOID($this->getSignatureOID()),
                DER::encodeNull()
            ]),
            DER::encodeBitString($this->savedSignature)
        ]);
        return $this->der;
    }

    public function getDER(): string { if (!$this->der) $this->sign(); return $this->der; }
    public function getPEM(): string { return PEM::encode($this->getDER(), 'CERTIFICATE'); }

    public function verify(): bool {
        if (!$this->der) return false;
        return $this->verifyWithIssuer($this->subjectKey);
    }

    public function verifyWithIssuer(RSA|ECDSA $issuerKey): bool {
        if (!$this->der || !$this->savedSignature) return false;
        if ($issuerKey instanceof ECDSA) {
            return $issuerKey->verify($this->tbsDer, $this->savedSignature);
        }
        $digest = hex2bin(Hash::hash($this->signatureAlgo, $this->tbsDer));
        return $issuerKey->verify($digest, $this->savedSignature, $this->signatureAlgo);
    }

    public static function fromPEM(string $pem): array {
        $info = PEM::decode($pem);
        return self::parseDER($info['data']);
    }

    public static function fromDER(string $der): array { return self::parseDER($der); }

    private static function parseDER(string $der): array {
        $parsed = DER::parse($der);
        $tbsChildren = $parsed['children'][0]['children'] ?? [];
        $serialIndex = (($tbsChildren[0]['tag'] ?? null) === 0xa0) ? 1 : 0;
        if (!isset(
            $tbsChildren[$serialIndex],
            $tbsChildren[$serialIndex + 2],
            $tbsChildren[$serialIndex + 3],
            $tbsChildren[$serialIndex + 4],
            $tbsChildren[$serialIndex + 5],
            $parsed['children'][1],
            $parsed['children'][2]
        )) {
            throw new \RuntimeException('Malformed X.509 certificate');
        }
        $sigValue = $parsed['children'][2];
        return [
            'serialNumber' => BigInt::fromBytes($tbsChildren[$serialIndex]['data']),
            'issuer' => $tbsChildren[$serialIndex + 2],
            'validity' => $tbsChildren[$serialIndex + 3],
            'subject' => $tbsChildren[$serialIndex + 4],
            'subjectPublicKeyInfo' => $tbsChildren[$serialIndex + 5],
            'signatureAlgorithm' => $parsed['children'][1]['children'][0]['oid'] ?? '',
            'signatureValue' => $sigValue['data'],
        ];
    }

    private function addDefaultExtensions(bool $isCA = false, ?int $pathLen = null): void {
        $hasKu = false;
        $hasBc = false;
        foreach ($this->extensions as $ext) {
            if ($ext->oid === Extension::KEY_USAGE) $hasKu = true;
            if ($ext->oid === Extension::BASIC_CONSTRAINTS) $hasBc = true;
        }
        if (!$hasBc) {
            $this->addExtension(Extension::makeBasicConstraints($isCA, $pathLen ?? ($isCA ? 0 : null)));
        }
        if (!$hasKu) {
            $bits = $isCA
                ? [1,1,0,0,0,1,1,0]
                : [1,0,0,0,0,0,0,0];
            $this->addExtension(Extension::makeKeyUsage($bits));
        }
        if ($isCA) {
            $hasSki = false;
            foreach ($this->extensions as $ext) {
                if ($ext->oid === Extension::SUBJECT_KEY_IDENTIFIER) $hasSki = true;
            }
            if (!$hasSki) {
                $this->addExtension(Extension::makeSubjectKeyIdentifier($this->computeSubjectKeyIdentifier()));
            }
        }
    }

    public static function createSelfSigned(RSA $key, array $subject, string $algo = 'sha256', int $days = 365): self {
        $cert = new self();
        $cert->setSubject($subject)->setIssuer($subject)
             ->setSubjectPublicKey($key)->setIssuerPrivateKey($key)
             ->setSignatureAlgorithm($algo)
             ->setValidity(time(), time() + $days * 86400);
        $cert->addDefaultExtensions(true);
        return $cert;
    }

    public static function createSelfSignedEC(ECDSA $key, array $subject, string $algo = 'sha256', int $days = 365): self {
        $cert = new self();
        $cert->setSubject($subject)->setIssuer($subject)
             ->setSubjectPublicKeyEC($key)->setIssuerPrivateKeyEC($key)
             ->setSignatureAlgorithm($algo)
             ->setValidity(time(), time() + $days * 86400);
        $cert->addDefaultExtensions(true);
        return $cert;
    }

    public static function createSigned(RSA $subjectKey, RSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365): self {
        $cert = new self();
        $cert->setSubject($subject)->setIssuer($issuer)
             ->setSubjectPublicKey($subjectKey)->setIssuerPrivateKey($caKey)
             ->setSignatureAlgorithm($algo)
             ->setValidity(time(), time() + $days * 86400);
        $cert->addDefaultExtensions(false);
        return $cert;
    }

    public static function createSignedEC(ECDSA $subjectKey, ECDSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365): self {
        $cert = new self();
        $cert->setSubject($subject)->setIssuer($issuer)
             ->setSubjectPublicKeyEC($subjectKey)->setIssuerPrivateKeyEC($caKey)
             ->setSignatureAlgorithm($algo)
             ->setValidity(time(), time() + $days * 86400);
        $cert->addDefaultExtensions(false);
        return $cert;
    }

    // --- Cross-signing (CA signed by another CA) ---

    public static function createCrossSigned(RSA $subjectKey, RSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365, ?int $pathLen = null): self {
        return self::createCrossSignedMixed($subjectKey, $caKey, $subject, $issuer, $algo, $days, $pathLen);
    }

    public static function createCrossSignedEC(ECDSA $subjectKey, ECDSA $caKey, array $subject, array $issuer, ?string $algo = null, int $days = 365, ?int $pathLen = null): self {
        return self::createCrossSignedMixed($subjectKey, $caKey, $subject, $issuer, $algo ?? 'sha256', $days, $pathLen);
    }

    public static function createCrossSignedMixed(RSA|ECDSA $subjectKey, RSA|ECDSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365, ?int $pathLen = null): self {
        $cert = new self();
        $cert->setSubject($subject)->setIssuer($issuer)
             ->setSubjectPublicKeyFromRSAOrEC($subjectKey)
             ->setIssuerPrivateKeyFromRSAOrEC($caKey);

        if ($caKey instanceof ECDSA) {
            // ECDSA hashes with its curve hash; the declared algorithm must match the curve pair
            $cert->setSignatureAlgorithm($caKey->getCurve()->hashAlgo);
        } else {
            $cert->setSignatureAlgorithm($algo);
        }
        $cert->setValidity(time(), time() + $days * 86400);
        $cert->addDefaultExtensions(true, $pathLen);
        $cert->ensureAuthorityKeyIdentifier($caKey);
        return $cert;
    }

    public static function crossSignCertificate(self $target, RSA|ECDSA $caKey, array $issuer, ?string $algo = null, int $days = 365, ?int $pathLen = null, bool $carryExtensions = true): self {
        $cross = new self();
        $cross->setSubject($target->getSubject())->setIssuer($issuer)
              ->setSubjectPublicKeyFromRSAOrEC($target->getSubjectKey())
              ->setIssuerPrivateKeyFromRSAOrEC($caKey)
              ->setValidity(time(), time() + $days * 86400);

        if ($caKey instanceof ECDSA) {
            $cross->setSignatureAlgorithm($caKey->getCurve()->hashAlgo);
        } else {
            $cross->setSignatureAlgorithm($algo ?? ($target->signatureAlgo ?? 'sha256'));
        }

        if ($carryExtensions) {
            foreach ($target->getExtensions() as $ext) {
                if ($ext->oid === Extension::AUTHORITY_KEY_IDENTIFIER || $ext->oid === Extension::BASIC_CONSTRAINTS) {
                    continue;
                }
                $cross->addExtension($ext);
            }
        }
        $cross->addDefaultExtensions(true, $pathLen);
        $cross->ensureAuthorityKeyIdentifier($caKey);
        return $cross;
    }

    private function ensureAuthorityKeyIdentifier(RSA|ECDSA $key): void {
        foreach ($this->extensions as $ext) {
            if ($ext->oid === Extension::AUTHORITY_KEY_IDENTIFIER) return;
        }
        $this->addExtension(Extension::makeAuthorityKeyIdentifier(self::keyIdentifier($key)));
    }
}
