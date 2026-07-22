<?php
declare(strict_types=1);
namespace FoxyCryptLib\Certificate;

use FoxyCryptLib\{BigInt, DER, PEM, Hash, Random, Symmetric\AES};

class PKCS12 {
    const VERSION = 3;

    // Bag IDs
    const BAG_KEY = '1.2.840.113549.1.12.10.1.1';
    const BAG_PKCS8_SHROUDED = '1.2.840.113549.1.12.10.1.2';
    const BAG_CERT = '1.2.840.113549.1.12.10.1.3';
    const BAG_CRL = '1.2.840.113549.1.12.10.1.4';
    const BAG_SECRET = '1.2.840.113549.1.12.10.1.5';
    const BAG_SAFE_CONTENTS = '1.2.840.113549.1.12.10.1.6';

    // Content types
    const CT_DATA = '1.2.840.113549.1.7.1';
    const CT_ENCRYPTED = '1.2.840.113549.1.7.6';
    const CT_ENVELOPED = '1.2.840.113549.1.7.3';

    // Encryption algorithms
    const PBE_SHA1_3DES = '1.2.840.113549.1.12.1.3';
    const PBE_SHA1_40BIT_RC2 = '1.2.840.113549.1.12.1.6';
    const PBES2 = '1.2.840.113549.1.5.13';
    const PBKDF2 = '1.2.840.113549.1.5.12';
    const AES_128_CBC = '2.16.840.1.101.3.4.1.2';
    const AES_256_CBC = '2.16.840.1.101.3.4.1.42';
    const HMAC_SHA1 = '1.2.840.113549.2.7';
    const HMAC_SHA256 = '1.2.840.113549.2.9';

    // Cert bag types
    const CERT_TYPE_X509 = '1.2.840.113549.1.9.22.1';
    const CERT_TYPE_SDSI = '1.2.840.113549.1.9.22.2';

    private array $certificates = [];
    private array $privateKeys = [];
    private int $iterations = 2048;
    private string $hashAlgo = 'sha256';

    public function __construct(
        private string $password = ''
    ) {}

    public function addCertificate(string $certDer): self {
        $this->certificates[] = $certDer;
        return $this;
    }

    public function addCertificateFromPEM(string $pem): self {
        $info = PEM::decode($pem);
        $this->certificates[] = $info['data'];
        return $this;
    }

    public function addPrivateKey(string $privateKeyDer, string $keyType = 'rsa'): self {
        $this->privateKeys[] = ['der' => $privateKeyDer, 'type' => $keyType];
        return $this;
    }

    public function setPassword(string $password): self {
        $this->password = $password;
        return $this;
    }

    public function setIterations(int $iterations): self {
        $this->iterations = $iterations;
        return $this;
    }

    public function setHashAlgorithm(string $algo): self {
        $this->hashAlgo = $algo;
        return $this;
    }

    public function encode(): string {
        $safeBags = [];

        // Add certificate bags
        foreach ($this->certificates as $certDer) {
            $safeBags[] = $this->encodeCertBag($certDer);
        }

        // Add private key bags (encrypted)
        foreach ($this->privateKeys as $keyInfo) {
            $safeBags[] = $this->encodeShroudedKeyBag($keyInfo['der'], $keyInfo['type']);
        }

        if (empty($safeBags)) {
            throw new \RuntimeException('No certificates or keys to encode');
        }

        $encodedSafeContents = DER::encodeSequence($safeBags);

        // authSafe wraps the SafeContents in a ContentInfo
        $authSafe = $this->encodeContentInfo(self::CT_DATA, DER::encodeOctetString($encodedSafeContents));

        // MAC
        $macSalt = Random::bytes(20);
        $macData = $this->encodeMacData($encodedSafeContents, $macSalt);

        // PFX
        $pfx = DER::encodeSequence([
            DER::encodeInteger(chr(self::VERSION)),
            $authSafe,
            $macData
        ]);

        return $pfx;
    }

    public function encodeToPEM(): string {
        return PEM::encode($this->encode(), 'PKCS12');
    }

    private function encodeContentInfo(string $contentType, string $content): string {
        return DER::encodeSequence([
            DER::encodeOID($contentType),
            DER::encodeContextSpecific(0, $content, true)
        ]);
    }

    private function encodeCertBag(string $certDer): string {
        $bagValue = DER::encodeSequence([
            DER::encodeOID(self::CERT_TYPE_X509),
            DER::encodeContextSpecific(0, DER::encodeOctetString($certDer), true)
        ]);
        return DER::encodeSequence([
            DER::encodeOID(self::BAG_CERT),
            DER::encodeContextSpecific(0, $bagValue, true)
        ]);
    }

    private function encodeShroudedKeyBag(string $keyDer, string $keyType): string {
        // Create PKCS#8 PrivateKeyInfo
        $pkcs8 = $this->createPKCS8PrivateKey($keyDer, $keyType);

        // Encrypt it
        $salt = Random::bytes(16);
        $iv = Random::bytes(16);
        $encKey = $this->deriveKey($salt, 32); // AES-256 key
        $aes = new AES($encKey);
        $encrypted = $aes->encryptCBC($pkcs8, $iv);

        $encAlgo = DER::encodeSequence([
            DER::encodeOID(self::PBES2),
            DER::encodeSequence([
                DER::encodeSequence([  // keyDerivationFunc
                    DER::encodeOID(self::PBKDF2),
                    DER::encodeSequence([
                        DER::encodeOctetString($salt),
                        DER::encodeInteger($this->encodeIntBytes($this->iterations)),
                        DER::encodeInteger(chr(32)),
                        DER::encodeSequence([
                            DER::encodeOID($this->hashAlgo === 'sha256' ? self::HMAC_SHA256 : self::HMAC_SHA1),
                            DER::encodeNull()
                        ])
                    ])
                ]),
                DER::encodeSequence([  // encryptionScheme
                    DER::encodeOID(self::AES_256_CBC),
                    DER::encodeOctetString($iv)
                ])
            ])
        ]);

        $encryptedKeyInfo = DER::encodeSequence([
            $encAlgo,
            DER::encodeOctetString($encrypted)
        ]);

        $bagValue = DER::encodeSequence([
            DER::encodeOID(self::BAG_PKCS8_SHROUDED),
            DER::encodeContextSpecific(0, $encryptedKeyInfo, true)
        ]);

        return $bagValue;
    }

    private function createPKCS8PrivateKey(string $keyDer, string $keyType): string {
        if ($keyType === 'ec') {
            // EC key is an ECPrivateKey SEQUENCE; wrap in PrivateKeyInfo
            $parsed = DER::parse($keyDer);
            $curveOid = '1.2.840.10045.2.1';
            foreach ($parsed['children'] as $child) {
                if (($child['tag'] & 0x1f) === 0 && isset($child['children'][0]['oid'])) {
                    $curveOid = $child['children'][0]['oid'];
                }
            }
            return DER::encodeSequence([
                DER::encodeInteger("\x00"),
                DER::encodeSequence([
                    DER::encodeOID('1.2.840.10045.2.1'),
                    DER::encodeOID($curveOid)
                ]),
                DER::encodeOctetString($keyDer)
            ]);
        }

        // RSA: wrap PKCS#1 in PKCS#8
        return DER::encodeSequence([
            DER::encodeInteger("\x00"),
            DER::encodeSequence([
                DER::encodeOID('1.2.840.113549.1.1.1'),
                DER::encodeNull()
            ]),
            DER::encodeOctetString($keyDer)
        ]);
    }

    private function encodeIntBytes(int $val): string {
        if ($val === 0) return "\x00";
        $bytes = '';
        while ($val > 0) {
            $bytes = chr($val & 0xff) . $bytes;
            $val >>= 8;
        }
        return $bytes;
    }

    private function deriveKey(string $salt, int $keyLen): string {
        return hex2bin(Hash::pbkdf2($this->hashAlgo, $this->password, $salt, $this->iterations, $keyLen));
    }

    private function encodeMacData(string $data, string $salt): string {
        // Use SHA-1 for MAC (standard PKCS#12)
        $macKey = hex2bin(Hash::pbkdf2('sha1', $this->password, $salt, $this->iterations, 20));
        $mac = hex2bin(Hash::hmac('sha1', $data, $macKey));

        return DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeSequence([
                    DER::encodeOID('1.3.14.3.2.26'), // SHA-1
                    DER::encodeNull()
                ]),
                DER::encodeOctetString($mac)
            ]),
            DER::encodeOctetString($salt),
            DER::encodeInteger($this->encodeIntBytes($this->iterations))
        ]);
    }

    // --- Decoding ---
    public static function decode(string $pfxDer, string $password): array {
        $pfx = DER::parse($pfxDer);
        $version = (int)BigInt::fromBytes($pfx['children'][0]['data'])->toInt();
        if ($version !== 3) throw new \RuntimeException("Unsupported PKCS12 version: $version");
        $authSafe = $pfx['children'][1];
        $macData = $pfx['children'][2] ?? null;

        // Extract content from authSafe
        $authSafeData = $authSafe['children'][1]['data'] ?? throw new \RuntimeException('Invalid authSafe');
        $outerParsed = DER::parse($authSafeData);
        $octetString = $outerParsed['data'] ?? $outerParsed['children'][0]['data'] ?? $authSafeData;
        $safeContentsDer = $octetString;
        $dataContent = DER::parse($safeContentsDer);

        // Verify MAC if present
        if ($macData) {
            $storedMac = $macData['children'][0]['children'][1]['data'];
            $salt = $macData['children'][1]['data'];
            $iterations = isset($macData['children'][2])
                ? (int)BigInt::fromBytes($macData['children'][2]['data'])->toInt()
                : 1;
            $macKey = hex2bin(Hash::pbkdf2('sha1', $password, $salt, $iterations, 20));
            $computedMac = hex2bin(Hash::hmac('sha1', $safeContentsDer, $macKey));
            if (!hash_equals($storedMac, $computedMac)) {
                throw new \RuntimeException('PKCS12 MAC verification failed (wrong password?)');
            }
        }

        // Parse SafeContents
        $safeContents = $dataContent;
        $certs = [];
        $keys = [];

        self::parseSafeContents($safeContents, $certs, $keys, $password);

        return ['certificates' => $certs, 'privateKeys' => $keys, 'version' => $version];
    }

    private static function parseSafeContents(array $container, array &$certs, array &$keys, string $password): void {
        foreach ($container['children'] ?? [] as $bag) {
            $bagId = $bag['children'][0]['oid'] ?? '';
            $bagValue = $bag['children'][1] ?? null;
            if (!$bagValue) continue;

            $innerData = $bagValue['data'];
            $parsed = DER::parse($innerData);

            if ($bagId === self::BAG_CERT) {
                $certType = $parsed['children'][0]['oid'] ?? '';
                if ($certType === self::CERT_TYPE_X509 && isset($parsed['children'][1])) {
                    $certs[] = $parsed['children'][1]['data'];
                }
            } elseif ($bagId === self::BAG_PKCS8_SHROUDED) {
                try {
                    $key = self::decryptShroudedKey($parsed, $password);
                    if ($key) $keys[] = $key;
                } catch (\Throwable) {}
            } elseif ($bagId === self::BAG_KEY) {
                try {
                    $keys[] = self::parsePlainKey($parsed);
                } catch (\Throwable) {}
            } elseif ($bagId === self::BAG_SAFE_CONTENTS) {
                self::parseSafeContents($parsed, $certs, $keys, $password);
            }
        }
    }

    private static function decryptShroudedKey(array $encKeyInfo, string $password): ?array {
        $encData = $encKeyInfo['children'][1]['data'] ?? '';

        $pbes2Oid = $encKeyInfo['children'][0]['children'][0]['oid'] ?? '';

        if ($pbes2Oid === self::PBES2) {
            $pbes2Params = $encKeyInfo['children'][0]['children'][1]['children'] ?? [];
            $kdfAlgo = $pbes2Params[0]['children'] ?? [];
            $encAlgo = $pbes2Params[1]['children'] ?? [];

            $pbkdf2Params = $kdfAlgo[1]['children'] ?? [];
            $salt = $pbkdf2Params[0]['data'] ?? '';

            $iter = isset($pbkdf2Params[1])
                ? (int)BigInt::fromBytes($pbkdf2Params[1]['data'])->toInt()
                : 2048;
            $keyLen = isset($pbkdf2Params[2])
                ? (int)BigInt::fromBytes($pbkdf2Params[2]['data'])->toInt()
                : 32;

            $iv = '';
            if (isset($encAlgo[1]) && $encAlgo[1]['tag'] === DER::TAG_OCTET_STRING) {
                $iv = $encAlgo[1]['data'];
            }

            $hashAlgo = 'sha1';
            if (isset($pbkdf2Params[3]['children'][0]['oid'])) {
                $hashAlgo = match ($pbkdf2Params[3]['children'][0]['oid']) {
                    self::HMAC_SHA256 => 'sha256',
                    self::HMAC_SHA1 => 'sha1',
                    default => 'sha1'
                };
            }

            $key = hex2bin(Hash::pbkdf2($hashAlgo, $password, $salt, $iter, $keyLen));
            $aes = new AES($key);
            $decrypted = $aes->decryptCBC($encData, $iv);

            return self::parsePKCS8PrivateKey($decrypted);
        }

        return null;
    }

    private static function parsePKCS8PrivateKey(string $pkcs8): ?array {
        try {
            $parsed = DER::parse($pkcs8);
            $algo = $parsed['children'][1]['children'][0]['oid'] ?? '';
            $privateKey = $parsed['children'][2]['data'] ?? '';

            $keyType = match ($algo) {
                '1.2.840.113549.1.1.1' => 'rsa',
                '1.2.840.10045.2.1' => 'ec',
                default => 'unknown'
            };

            return [
                'type' => $keyType,
                'algorithm' => $algo,
                'pkcs8' => $pkcs8,
                'privateKey' => $privateKey
            ];
        } catch (\Throwable) {
            return null;
        }
    }

    private static function parsePlainKey(array $parsed): ?array {
        return self::parsePKCS8PrivateKey($parsed['data'] ?? $parsed['raw'] ?? '');
    }
}
