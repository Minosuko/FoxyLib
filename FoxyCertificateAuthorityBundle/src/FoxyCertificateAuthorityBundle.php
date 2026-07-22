<?php
declare(strict_types=1);
namespace FoxyCertificateAuthorityBundle;

use FoxyCryptLib\{RSA, DER, PEM, Hash, BigInt};
use FoxyCryptLib\Certificate\{CABundle, Extension};

class FoxyCertificateAuthorityBundle {

    private CABundle $trustStore;
    private string $bundleDir;
    private string $remoteBaseUrl = 'https://minosuko.id.vn/foxy/cabundle/%s.pem';

    private const SIG_OID_TO_HASH = [
        '1.2.840.113549.1.1.4' => 'md5',
        '1.2.840.113549.1.1.5' => 'sha1',
        '1.2.840.113549.1.1.14' => 'sha224',
        '1.2.840.113549.1.1.11' => 'sha256',
        '1.2.840.113549.1.1.12' => 'sha384',
        '1.2.840.113549.1.1.13' => 'sha512',
        '1.2.840.10045.4.3.2' => 'sha256',
        '1.2.840.10045.4.3.3' => 'sha384',
        '1.2.840.10045.4.3.4' => 'sha512',
    ];

    public function __construct() {
        $this->trustStore = new CABundle();
        $this->bundleDir = __DIR__ . '/../bundle';
    }

    public function setRemoteBaseUrl(string $url): self {
        $this->remoteBaseUrl = rtrim($url, '/') . '/%s.pem';
        return $this;
    }

    public function getTrustStore(): CABundle {
        return $this->trustStore;
    }

    public function loadBundles(): self {
        $cabundle = $this->bundleDir . '/cabundle.pem';
        if (file_exists($cabundle)) {
            $this->trustStore->loadFile($cabundle);
        }
        $foxybundle = $this->bundleDir . '/foxycabundle.pem';
        if (file_exists($foxybundle)) {
            $this->trustStore->loadFile($foxybundle);
        }
        return $this;
    }

    public function addPEM(string $pem): self {
        $this->trustStore->loadPEM($pem);
        return $this;
    }

    public function addFile(string $path): self {
        $this->trustStore->loadFile($path);
        return $this;
    }

    public function getCertificates(): array {
        return $this->trustStore->getCertificates();
    }

    public function fetchChain(string $certIdentifier): string {
        $url = sprintf($this->remoteBaseUrl, rawurlencode($certIdentifier));
        $context = stream_context_create([
            'http' => [
                'timeout' => 15,
                'user_agent' => 'FoxyCertificateAuthorityBundle/1.0',
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            throw new \RuntimeException("Failed to fetch certificate chain from: $url");
        }
        return $result;
    }

    public function fetchAndVerify(string $certIdentifier): array {
        try {
            $chainPem = $this->fetchChain($certIdentifier);
            return $this->verify($chainPem);
        } catch (\RuntimeException $e) {
            return ['valid' => false, 'chainRooted' => false, 'certs' => [], 'error' => $e->getMessage()];
        }
    }

    public function verify(string $certPem): array {
        $parsed = $this->parsePEM($certPem);
        if (empty($parsed)) {
            return ['valid' => false, 'chainRooted' => false, 'certs' => []];
        }

        $leaf = null;
        foreach ($parsed as $p) {
            if (($p['basicConstraints']['ca'] ?? false) === false) {
                $leaf = $p;
                break;
            }
        }
        if (!$leaf) $leaf = $parsed[0];

        $chain = [$leaf];
        $current = $leaf;
        $visited = [];

        while (true) {
            if ($current['issuer']['encoded'] === $current['subject']['encoded']) {
                break;
            }
            $issuer = $this->findIssuer($current);
            if (!$issuer) break;
            $key = md5($issuer['der'] ?? '');
            if (isset($visited[$key])) break;
            $visited[$key] = true;
            $chain[] = $issuer;
            $current = $issuer;
        }

        $results = [];
        foreach ($chain as $i => $cert) {
            $trusted = $this->verifyCertificate($cert);
            $sigValid = ($i === 0) || $this->verifySignature($chain[$i - 1], $cert);
            $selfSigned = $cert['issuer']['encoded'] === $cert['subject']['encoded'];

            $results[] = [
                'subject' => $cert['subject']['encoded'] ?? '',
                'serialNumber' => $cert['serialNumber']->toHex(),
                'isCA' => $cert['basicConstraints']['ca'],
                'selfSigned' => $selfSigned,
                'trusted' => $trusted,
                'signatureValid' => $sigValid,
                'valid' => $sigValid && ($trusted || !$selfSigned),
            ];
        }

        $chainRooted = false;
        foreach ($results as $r) {
            if ($r['trusted'] && $r['signatureValid']) {
                $chainRooted = true;
                break;
            }
        }

        return [
            'valid' => ($results[0]['valid'] ?? false) && $chainRooted,
            'chainRooted' => $chainRooted,
            'certs' => $results,
        ];
    }

    private function findIssuer(array $cert): ?array {
        $aki = $cert['authorityKeyIdentifier']['keyIdentifier'] ?? '';
        if ($aki) {
            foreach ($this->trustStore->getCertificates() as $cand) {
                $candSki = $cand['subjectKeyIdentifier'] ?? '';
                if ($candSki && $candSki === $aki) {
                    return $cand;
                }
            }
        }
        return $this->trustStore->findByIssuerOf($cert);
    }

    public function buildChain(string $certPem): array {
        $parsed = $this->parseSinglePEM($certPem);
        return CABundle::buildChain($parsed, $this->trustStore);
    }

    public function isTrusted(array $cert): bool {
        return $this->verifyCertificate($cert) === true;
    }

    public function verifyCertificate(array $cert): bool {
        $certs = $this->trustStore->getCertificates();
        foreach ($certs as $c) {
            if ($c['subject']['encoded'] === $cert['subject']['encoded'] &&
                $c['subjectKeyIdentifier'] === $cert['subjectKeyIdentifier']) {
                return true;
            }
        }
        return false;
    }

    private function parsePEM(string $pem): array {
        $certs = [];
        $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $pem));
        $current = '';
        $in = false;
        foreach ($lines as $line) {
            $t = trim($line);
            if (str_starts_with($t, '-----BEGIN ')) {
                $current = $t . "\n";
                $in = true;
            } elseif ($in) {
                $current .= $line . "\n";
                if (str_starts_with($t, '-----END ')) {
                    $parsed = $this->parseSinglePEM($current);
                    if ($parsed) $certs[] = $parsed;
                    $current = '';
                    $in = false;
                }
            }
        }
        return $certs;
    }

    private function parseSinglePEM(string $pem): ?array {
        try {
            $info = PEM::decode($pem);
            return $this->parseCertDER($info['data']);
        } catch (\Throwable) {
            return null;
        }
    }

    private function parseCertDER(string $der): ?array {
        try {
            $parsed = DER::parse($der);
            $tbs = $parsed['children'][0];
            $tbsChildren = $tbs['children'] ?? [];
            $tbsRaw = $tbs['raw'];

            $issuerEncoded = $tbsChildren[3]['raw'] ?? '';
            $subjectEncoded = $tbsChildren[5]['raw'] ?? '';
            $spki = $tbsChildren[6] ?? null;

            $sigAlgoOid = $parsed['children'][1]['children'][0]['oid'] ?? '';
            $sigBitString = $parsed['children'][2]['data'] ?? '';
            $sigValue = strlen($sigBitString) > 0 ? substr($sigBitString, 1) : '';

            $isCA = false;
            $pathLen = null;
            $ski = '';
            $aki = '';

            foreach ($tbsChildren as $child) {
                if (($child['tag'] & 0x1f) === 3) {
                    $extSeq = $child['children'][0] ?? null;
                    if ($extSeq) {
                        foreach ($extSeq['children'] ?? [] as $ext) {
                            $c = $ext['children'] ?? [];
                            $oid = $c[0]['oid'] ?? '';
                            $hasCritical = isset($c[1]) && $c[1]['tag'] === DER::TAG_BOOLEAN;
                            $di = $hasCritical ? 2 : 1;
                            $d = $c[$di]['data'] ?? '';

                            if ($oid === Extension::BASIC_CONSTRAINTS) {
                                try {
                                    $bc = Extension::decodeBasicConstraints(DER::parse($d));
                                    $isCA = $bc['ca'] ?? false;
                                    $pathLen = $bc['pathLen'] ?? null;
                                } catch (\Throwable) {}
                            } elseif ($oid === Extension::SUBJECT_KEY_IDENTIFIER) {
                                try {
                                    $ski = Extension::decodeSubjectKeyIdentifier(DER::parse($d));
                                } catch (\Throwable) {}
                            } elseif ($oid === Extension::AUTHORITY_KEY_IDENTIFIER) {
                                try {
                                    $aki = Extension::decodeAuthorityKeyIdentifier(DER::parse($d));
                                } catch (\Throwable) {}
                            }
                        }
                    }
                    break;
                }
            }

            if (!$ski && $spki) {
                $ski = hex2bin(Hash::hash('sha1', $spki['raw']));
            }

            $pubKey = null;
            try {
                $alg = $spki['children'][0]['children'][0]['oid'] ?? '';
                if ($alg === '1.2.840.113549.1.1.1') {
                    $keyBits = substr($spki['children'][1]['data'] ?? '', 1);
                    $pkParsed = DER::parse($keyBits);
                    $pubKey = RSA::fromPublicKey(
                        BigInt::fromBytes($pkParsed['children'][0]['data']),
                        BigInt::fromBytes($pkParsed['children'][1]['data'])
                    );
                }
            } catch (\Throwable) {}

            return [
                'der' => $der,
                'tbsDer' => $tbsRaw,
                'serialNumber' => BigInt::fromBytes($tbsChildren[1]['data'] ?? ''),
                'issuer' => ['encoded' => $issuerEncoded],
                'subject' => ['encoded' => $subjectEncoded],
                'subjectPublicKeyInfo' => $spki ? ['raw' => $spki['raw']] : [],
                'subjectPublicKey' => $pubKey,
                'signatureAlgorithm' => $sigAlgoOid,
                'signatureValue' => $sigValue,
                'basicConstraints' => ['ca' => $isCA, 'pathLen' => $pathLen],
                'subjectKeyIdentifier' => $ski,
                'authorityKeyIdentifier' => $aki ?: null,
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function verifySignature(array $childCert, array $parentCert): bool {
        if (empty($childCert['signatureValue']) || empty($childCert['tbsDer'])) {
            return false;
        }

        $pubKey = $parentCert['subjectPublicKey'] ?? null;
        if (!$pubKey instanceof RSA) {
            $spki = $parentCert['subjectPublicKeyInfo'] ?? [];
            if (($spki['algorithm'] ?? '') === 'rsa' && isset($spki['n']) && isset($spki['e'])) {
                $pubKey = RSA::fromPublicKey($spki['n'], $spki['e']);
            }
        }
        if (!$pubKey instanceof RSA) {
            return false;
        }

        $hashAlgo = self::SIG_OID_TO_HASH[$childCert['signatureAlgorithm']] ?? 'sha256';
        $digest = hex2bin(Hash::hash($hashAlgo, $childCert['tbsDer']));

        try {
            return $pubKey->verify($digest, $childCert['signatureValue'], $hashAlgo);
        } catch (\Throwable) {
            return false;
        }
    }

    public function getBundleDir(): string {
        return $this->bundleDir;
    }
}
