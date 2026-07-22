<?php
declare(strict_types=1);
namespace FoxyCryptLib\Certificate;

use FoxyCryptLib\{BigInt, DER, PEM, Hash};

class CRL {
    private array $entries = [];
    private array $issuer = [];
    private array $extensions = [];
    private int $thisUpdate;
    private int $nextUpdate;
    private ?object $signerKey = null;
    private string $keyType = 'rsa';
    private string $signatureAlgo = 'sha256';
    private string $der = '';
    private string $tbsDer = '';
    private string $savedSignature = '';
    private ?string $crlNumber = null;

    public function __construct() {
        $this->thisUpdate = time();
        $this->nextUpdate = time() + 7 * 86400;
    }

    public function setIssuer(array $issuer): self { $this->issuer = $issuer; return $this; }
    public function setThisUpdate(int $time): self { $this->thisUpdate = $time; return $this; }
    public function setNextUpdate(int $time): self { $this->nextUpdate = $time; return $this; }
    public function setSignatureAlgorithm(string $algo): self { $this->signatureAlgo = $algo; return $this; }
    public function setCRLNumber(int $number): self {
        $bytes = '';
        while ($number > 0) {
            $bytes = chr($number & 0xff) . $bytes;
            $number >>= 8;
        }
        if ($bytes === '') $bytes = "\x00";
        if (ord($bytes[0]) & 0x80) $bytes = "\x00" . $bytes;
        $this->crlNumber = $bytes;
        return $this;
    }

    public function setSignerKeyRSA(\FoxyCryptLib\RSA $key): self {
        $this->signerKey = $key; $this->keyType = 'rsa'; return $this;
    }

    public function setSignerKeyEC(\FoxyCryptLib\ECDSA $key): self {
        $this->signerKey = $key; $this->keyType = 'ec'; return $this;
    }

    public function addEntry(BigInt $serialNumber, int $revocationDate, ?int $reason = null, ?int $invalidityDate = null): self {
        $entry = [
            'serialNumber' => $serialNumber,
            'revocationDate' => $revocationDate,
        ];
        $extensions = [];
        if ($reason !== null) {
            $extensions[] = new Extension(Extension::REASON_CODE, false, $reason);
        }
        if ($invalidityDate !== null) {
            $extensions[] = new Extension(Extension::INVALIDITY_DATE, false, $invalidityDate);
        }
        if ($extensions) {
            $entry['extensions'] = $extensions;
        }
        $this->entries[] = $entry;
        return $this;
    }

    public function addExtensions(array $exts): self {
        $this->extensions = array_merge($this->extensions, $exts);
        return $this;
    }

    public function sign(): string {
        if (!$this->signerKey) throw new \RuntimeException('Signer key required');

        $sigOid = $this->getSignatureOID();
        $tbsParts = [
            DER::encodeInteger("\x01"), // version (v2)
            DER::encodeSequence([       // signature AlgorithmIdentifier
                DER::encodeOID($sigOid),
                DER::encodeNull()
            ]),
            $this->encodeName($this->issuer),
            self::encodeTimeValue($this->thisUpdate),
            self::encodeTimeValue($this->nextUpdate),
        ];

        // Revoked certificates
        if ($this->entries) {
            $revokedCerts = [];
            foreach ($this->entries as $entry) {
                $parts = [
                    DER::encodeInteger($entry['serialNumber']->toBytes()),
                    self::encodeTimeValue($entry['revocationDate']),
                ];
                if (!empty($entry['extensions'])) {
                    $extChildren = [];
                    foreach ($entry['extensions'] as $ext) {
                        $extChildren[] = $ext->encode();
                    }
                    $parts[] = DER::encodeSequence($extChildren);
                }
                $revokedCerts[] = DER::encodeSequence($parts);
            }
            $tbsParts[] = DER::encodeSequence($revokedCerts);
        }

        // CRL extensions
        $extChildren = [];
        if ($this->crlNumber !== null) {
            $extChildren[] = (new Extension(
                Extension::CRL_NUMBER,
                false,
                $this->crlNumber
            ))->encode();
        }
        foreach ($this->extensions as $ext) {
            $extChildren[] = $ext->encode();
        }
        if ($extChildren) {
            $tbsParts[] = DER::encodeContextSpecific(0, DER::encodeSequence($extChildren));
        }

        $this->tbsDer = DER::encodeSequence($tbsParts);
        $digest = hex2bin(Hash::hash($this->signatureAlgo, $this->tbsDer));

        if ($this->keyType === 'ec') {
            $this->savedSignature = $this->signerKey->sign($this->tbsDer);
        } else {
            $this->savedSignature = $this->signerKey->sign($digest, $this->signatureAlgo);
        }

        $sigOid = $this->getSignatureOID();
        $this->der = DER::encodeSequence([
            $this->tbsDer,
            DER::encodeSequence([
                DER::encodeOID($sigOid),
                DER::encodeNull()
            ]),
            DER::encodeBitString($this->savedSignature)
        ]);
        return $this->der;
    }

    public function getDER(): string { if (!$this->der) $this->sign(); return $this->der; }
    public function getPEM(): string { return PEM::encode($this->getDER(), 'X509 CRL'); }

    private function getSignatureOID(): string {
        if ($this->keyType === 'ec') {
            $map = ['sha256' => '1.2.840.10045.4.3.2', 'sha384' => '1.2.840.10045.4.3.3', 'sha512' => '1.2.840.10045.4.3.4'];
            return $map[$this->signatureAlgo] ?? '1.2.840.10045.4.3.2';
        }
        $map = ['sha256' => '1.2.840.113549.1.1.11', 'sha384' => '1.2.840.113549.1.1.12', 'sha512' => '1.2.840.113549.1.1.13'];
        return $map[$this->signatureAlgo] ?? '1.2.840.113549.1.1.11';
    }

    private function encodeName(array $name): string {
        $rdns = [];
        $oidMap = [
            'CN' => '2.5.4.3', 'commonName' => '2.5.4.3',
            'O' => '2.5.4.10', 'organizationName' => '2.5.4.10',
            'OU' => '2.5.4.11', 'L' => '2.5.4.7', 'ST' => '2.5.4.8',
            'C' => '2.5.4.6', 'E' => '1.2.840.113549.1.9.1',
            'emailAddress' => '1.2.840.113549.1.9.1',
            'DC' => '0.9.2342.19200300.100.1.25',
        ];
        foreach ($name as $key => $value) {
            $oid = $oidMap[$key] ?? $key;
            $isPrintable = preg_match('/^[A-Za-z0-9 \'\(\)\+\,\-\.\/\:\=\?]+$/', $value) === 1;
            $strEnc = $isPrintable ? DER::encodePrintableString($value) : DER::encodeUTF8String($value);
            $rdns[] = DER::encodeSet([DER::encodeSequence([DER::encodeOID($oid), $strEnc])]);
        }
        return DER::encodeSequence($rdns);
    }

    private static function encodeTimeValue(int $timestamp): string {
        $dt = new \DateTimeImmutable("@$timestamp");
        return DER::encodeTime($dt, $dt->format('Y') < '2050');
    }

    // --- Decoding ---
    public static function fromDER(string $der): array {
        $parsed = DER::parse($der);
        $tbs = $parsed['children'][0];
        $children = $tbs['children'];

        $result = [
            'version' => isset($children[0]) ? (int)BigInt::fromBytes($children[0]['data'])->toInt() + 1 : 1,
            'signature' => $children[1]['children'][0]['oid'] ?? '',
            'issuer' => $children[2] ?? [],
            'thisUpdate' => $children[3]['data'] ?? '',
            'nextUpdate' => $children[4]['data'] ?? '',
            'revokedCertificates' => [],
            'extensions' => [],
            'signatureAlgorithm' => $parsed['children'][1]['children'][0]['oid'] ?? '',
            'signatureValue' => $parsed['children'][2]['data'] ?? '',
        ];

        $idx = 5;
        // Check for revoked certificates list
        if (isset($children[$idx]) && ($children[$idx]['tag'] === DER::TAG_SEQUENCE)) {
            foreach ($children[$idx]['children'] as $entry) {
                $exts = [];
                $e = [
                    'serialNumber' => BigInt::fromBytes($entry['children'][0]['data']),
                    'revocationDate' => $entry['children'][1]['data'],
                ];
                // Check for entry extensions
                $entryChildren = $entry['children'] ?? [];
                if (isset($entryChildren[2])) {
                    foreach ($entryChildren[2]['children'] ?? [] as $extChild) {
                        try {
                            $c = $extChild['children'] ?? [];
                            $eid = $c[0]['oid'] ?? '';
                            $critical = isset($c[1]) && $c[1]['tag'] === DER::TAG_BOOLEAN;
                            $dataIdx = $critical ? 2 : 1;
                            $edata = $c[$dataIdx]['data'] ?? '';
                            $exts[] = [
                                'oid' => $eid,
                                'critical' => $critical,
                                'value' => Extension::decodeValue($eid, $edata)
                            ];
                        } catch (\Throwable) {}
                    }
                    $e['extensions'] = $exts;
                }
                $result['revokedCertificates'][] = $e;
            }
            $idx++;
        }

        // CRL extensions (context-specific tag 0)
        if (isset($children[$idx]) && ($children[$idx]['tag'] & 0x1f) === 0) {
            $extSequence = $children[$idx]['children'][0] ?? null;
            if ($extSequence) {
                foreach ($extSequence['children'] ?? [] as $extChild) {
                    try {
                        $c = $extChild['children'] ?? [];
                        $eid = $c[0]['oid'] ?? '';
                        $critical = isset($c[1]) && $c[1]['tag'] === DER::TAG_BOOLEAN;
                        $dataIdx = $critical ? 2 : 1;
                        $edata = $c[$dataIdx]['data'] ?? '';
                        $result['extensions'][] = [
                            'oid' => $eid,
                            'critical' => $critical,
                            'value' => Extension::decodeValue($eid, $edata)
                        ];
                    } catch (\Throwable) {}
                }
            }
        }

        return $result;
    }

    public static function fromPEM(string $pem): array {
        $info = PEM::decode($pem);
        return self::fromDER($info['data']);
    }
}
