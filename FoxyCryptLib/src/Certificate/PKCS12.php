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
    const HMAC_SHA384 = '1.2.840.113549.2.10';
    const HMAC_SHA512 = '1.2.840.113549.2.11';

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
            $digestInfo = $macData['children'][0];
            $macOid = $digestInfo['children'][0]['children'][0]['oid'] ?? '';
            $macHash = self::hashOidToName($macOid);
            $storedMac = $digestInfo['children'][1]['data'];
            $salt = $macData['children'][1]['data'];
            $iterations = isset($macData['children'][2])
                ? (int)BigInt::fromBytes($macData['children'][2]['data'])->toInt()
                : 1;
            $macKey = self::pkcs12Kdf($macHash, $password, $salt, $iterations, 3, strlen($storedMac));
            $computedMac = hex2bin(Hash::hmac($macHash, $safeContentsDer, $macKey));
            // Keep compatibility with bundles produced by older FoxyCryptLib versions.
            $legacyKey = hex2bin(Hash::pbkdf2('sha1', $password, $salt, $iterations, 20));
            $legacyMac = hex2bin(Hash::hmac('sha1', $safeContentsDer, $legacyKey));
            if (!hash_equals($storedMac, $computedMac) && !hash_equals($storedMac, $legacyMac)) {
                throw new \RuntimeException('PKCS12 MAC verification failed (wrong password?)');
            }
        }

        // Parse SafeContents
        $safeContents = $dataContent;
        $certs = [];
        $keys = [];

        $firstContentOid = $dataContent['children'][0]['children'][0]['oid'] ?? '';
        if (in_array($firstContentOid, [self::CT_DATA, self::CT_ENCRYPTED, self::CT_ENVELOPED], true)) {
            foreach ($dataContent['children'] as $contentInfo) {
                self::parseAuthenticatedSafeContent($contentInfo, $certs, $keys, $password);
            }
        } else {
            self::parseSafeContents($dataContent, $certs, $keys, $password);
        }

        return ['certificates' => $certs, 'privateKeys' => $keys, 'version' => $version];
    }

    private static function parseAuthenticatedSafeContent(
        array $contentInfo,
        array &$certs,
        array &$keys,
        string $password
    ): void {
        $contentType = $contentInfo['children'][0]['oid'] ?? '';
        $wrapped = $contentInfo['children'][1]['children'][0] ?? null;
        if ($wrapped === null) {
            throw new \RuntimeException('Invalid PKCS12 AuthenticatedSafe content');
        }
        if ($contentType === self::CT_DATA) {
            self::parseSafeContents(DER::parse($wrapped['data']), $certs, $keys, $password);
            return;
        }
        if ($contentType === self::CT_ENCRYPTED) {
            $encryptedContentInfo = $wrapped['children'][1] ?? null;
            $algorithm = $encryptedContentInfo['children'][1] ?? null;
            $ciphertext = $encryptedContentInfo['children'][2]['data'] ?? null;
            if ($algorithm === null || !is_string($ciphertext)) {
                throw new \RuntimeException('Invalid encrypted PKCS12 SafeContents');
            }
            $plaintext = self::decryptWithAlgorithm($algorithm, $ciphertext, $password);
            self::parseSafeContents(DER::parse($plaintext), $certs, $keys, $password);
            return;
        }
        throw new \RuntimeException("Unsupported PKCS12 content type: {$contentType}");
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
                    $certs[] = $parsed['children'][1]['children'][0]['data']
                        ?? $parsed['children'][1]['data'];
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
        $algorithm = $encKeyInfo['children'][0] ?? null;
        if ($algorithm === null) return null;
        return self::parsePKCS8PrivateKey(self::decryptWithAlgorithm($algorithm, $encData, $password));
    }

    private static function decryptWithAlgorithm(array $algorithm, string $ciphertext, string $password): string {
        $oid = $algorithm['children'][0]['oid'] ?? '';
        if ($oid !== self::PBES2) {
            throw new \RuntimeException("Unsupported PKCS12 encryption algorithm: {$oid}");
        }
        $params = $algorithm['children'][1]['children'] ?? [];
        $kdf = $params[0]['children'] ?? [];
        $encryption = $params[1]['children'] ?? [];
        if (($kdf[0]['oid'] ?? '') !== self::PBKDF2) {
            throw new \RuntimeException('PKCS12 PBES2 requires PBKDF2');
        }
        $pbkdf2 = $kdf[1]['children'] ?? [];
        $salt = $pbkdf2[0]['data'] ?? '';
        $iterations = isset($pbkdf2[1]['data'])
            ? BigInt::fromBytes($pbkdf2[1]['data'])->toInt()
            : 1;
        if ($iterations < 1 || $iterations > 10000000) {
            throw new \RuntimeException('Invalid PKCS12 PBKDF2 iteration count');
        }
        $encryptionOid = $encryption[0]['oid'] ?? '';
        $keyLength = match ($encryptionOid) {
            self::AES_128_CBC => 16,
            self::AES_256_CBC => 32,
            default => throw new \RuntimeException("Unsupported PKCS12 PBES2 cipher: {$encryptionOid}"),
        };
        $prfIndex = 2;
        if (isset($pbkdf2[2]) && $pbkdf2[2]['tag'] === DER::TAG_INTEGER) {
            $keyLength = BigInt::fromBytes($pbkdf2[2]['data'])->toInt();
            $prfIndex = 3;
        }
        $prfOid = $pbkdf2[$prfIndex]['children'][0]['oid'] ?? self::HMAC_SHA1;
        $hashAlgo = self::prfOidToName($prfOid);
        $iv = $encryption[1]['data'] ?? '';
        if (strlen($iv) !== 16) {
            throw new \RuntimeException('Invalid PKCS12 AES initialization vector');
        }
        $key = hex2bin(Hash::pbkdf2($hashAlgo, $password, $salt, $iterations, $keyLength));
        return (new AES($key))->decryptCBC($ciphertext, $iv);
    }

    private static function hashOidToName(string $oid): string {
        return match ($oid) {
            '1.3.14.3.2.26' => 'sha1',
            '2.16.840.1.101.3.4.2.1' => 'sha256',
            '2.16.840.1.101.3.4.2.2' => 'sha384',
            '2.16.840.1.101.3.4.2.3' => 'sha512',
            default => throw new \RuntimeException("Unsupported PKCS12 MAC hash: {$oid}"),
        };
    }

    private static function prfOidToName(string $oid): string {
        return match ($oid) {
            self::HMAC_SHA1 => 'sha1',
            self::HMAC_SHA256 => 'sha256',
            self::HMAC_SHA384 => 'sha384',
            self::HMAC_SHA512 => 'sha512',
            default => throw new \RuntimeException("Unsupported PKCS12 PBKDF2 PRF: {$oid}"),
        };
    }

    private static function pkcs12Kdf(
        string $hashAlgo,
        string $password,
        string $salt,
        int $iterations,
        int $id,
        int $length
    ): string {
        if ($iterations < 1 || $iterations > 10000000) {
            throw new \RuntimeException('Invalid PKCS12 KDF iteration count');
        }
        $u = strlen(hex2bin(Hash::hash($hashAlgo, '')));
        $v = in_array($hashAlgo, ['sha384', 'sha512'], true) ? 128 : 64;
        $passwordBytes = self::passwordToBmpString($password);
        $expand = static function (string $value, int $blockSize): string {
            if ($value === '') return '';
            $target = $blockSize * (int)ceil(strlen($value) / $blockSize);
            return substr(str_repeat($value, (int)ceil($target / strlen($value))), 0, $target);
        };
        $diversifier = str_repeat(chr($id), $v);
        $iBuffer = $expand($salt, $v) . $expand($passwordBytes, $v);
        $result = '';
        for ($block = 0; strlen($result) < $length; $block++) {
            $a = hex2bin(Hash::hash($hashAlgo, $diversifier . $iBuffer));
            for ($round = 1; $round < $iterations; $round++) {
                $a = hex2bin(Hash::hash($hashAlgo, $a));
            }
            $result .= $a;
            if ($iBuffer === '') continue;
            $b = substr(str_repeat($a, (int)ceil($v / $u)), 0, $v);
            for ($offset = 0; $offset < strlen($iBuffer); $offset += $v) {
                $carry = 1;
                for ($index = $v - 1; $index >= 0; $index--) {
                    $sum = ord($iBuffer[$offset + $index]) + ord($b[$index]) + $carry;
                    $iBuffer[$offset + $index] = chr($sum & 0xff);
                    $carry = $sum >> 8;
                }
            }
        }
        return substr($result, 0, $length);
    }

    private static function passwordToBmpString(string $password): string {
        $result = '';
        for ($offset = 0; $offset < strlen($password);) {
            $first = ord($password[$offset++]);
            if ($first < 0x80) {
                $codepoint = $first;
            } elseif (($first & 0xe0) === 0xc0 && $offset < strlen($password)) {
                $codepoint = (($first & 0x1f) << 6) | (ord($password[$offset++]) & 0x3f);
            } elseif (($first & 0xf0) === 0xe0 && $offset + 1 < strlen($password)) {
                $codepoint = (($first & 0x0f) << 12)
                    | ((ord($password[$offset++]) & 0x3f) << 6)
                    | (ord($password[$offset++]) & 0x3f);
            } elseif (($first & 0xf8) === 0xf0 && $offset + 2 < strlen($password)) {
                $codepoint = (($first & 0x07) << 18)
                    | ((ord($password[$offset++]) & 0x3f) << 12)
                    | ((ord($password[$offset++]) & 0x3f) << 6)
                    | (ord($password[$offset++]) & 0x3f);
            } else {
                throw new \RuntimeException('PKCS12 password is not valid UTF-8');
            }
            if ($codepoint <= 0xffff) {
                $result .= pack('n', $codepoint);
            } else {
                $codepoint -= 0x10000;
                $result .= pack('nn', 0xd800 | ($codepoint >> 10), 0xdc00 | ($codepoint & 0x3ff));
            }
        }
        return $result . "\x00\x00";
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
