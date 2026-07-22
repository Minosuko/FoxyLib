<?php
declare(strict_types=1);
namespace FoxyCryptLib\Certificate;

use FoxyCryptLib\{BigInt, DER, PEM, Hash, Accel};

class CABundle {
    private array $trustedCerts = [];

    public function __construct() {}

    public function loadPEM(string $pemData): self {
        $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $pemData));
        $currentPem = '';
        $inCert = false;
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if (str_starts_with($trimmed, '-----BEGIN ')) {
                $currentPem = $trimmed . "\n";
                $inCert = true;
            } elseif ($inCert) {
                $currentPem .= $line . "\n";
                if (str_starts_with($trimmed, '-----END ')) {
                    $this->addPEMCertificate($currentPem);
                    $currentPem = '';
                    $inCert = false;
                }
            }
        }
        return $this;
    }

    public function loadFile(string $path): self {
        if (!file_exists($path)) throw new \RuntimeException("CA bundle file not found: $path");
        return $this->loadPEM(file_get_contents($path));
    }

    public function addPEMCertificate(string $pem): self {
        try {
            $info = PEM::decode($pem);
            $parsed = $this->parseCertDER($info['data']);
            $this->trustedCerts[] = $parsed;
        } catch (\Throwable $e) {
            // skip invalid certs in bundle
        }
        return $this;
    }

    public function addDERCertificate(string $der): self {
        try {
            $this->trustedCerts[] = $this->parseCertDER($der);
        } catch (\Throwable) {}
        return $this;
    }

    public function getCertificates(): array {
        return $this->trustedCerts;
    }

    public function findBySubject(array $rdn): ?array {
        $subjectDer = $this->encodeRDN($rdn);
        foreach ($this->trustedCerts as $cert) {
            if ($cert['subject']['encoded'] === $subjectDer) {
                return $cert;
            }
        }
        return null;
    }

    public function findByIssuerOf(array $cert): ?array {
        $issuerDer = $cert['issuer']['encoded'] ?? '';
        foreach ($this->trustedCerts as $cand) {
            if (($cand['subject']['encoded'] ?? '') === $issuerDer) {
                return $cand;
            }
        }
        return null;
    }

    public function findCandidatesFor(array $cert): array {
        $issuerDer = $cert['issuer']['encoded'] ?? '';
        $candidates = [];
        foreach ($this->trustedCerts as $cand) {
            if (($cand['subject']['encoded'] ?? '') === $issuerDer) {
                $candidates[] = $cand;
            }
        }
        return $candidates;
    }

    public function findCACerts(): array {
        return array_values(array_filter($this->trustedCerts, fn($c) =>
            ($c['basicConstraints']['ca'] ?? false) === true
        ));
    }

    public function findEndEntityCerts(): array {
        return array_values(array_filter($this->trustedCerts, fn($c) =>
            ($c['basicConstraints']['ca'] ?? true) === false
        ));
    }

    private function parseCertDER(string $der): array {
        $parsed = DER::parse($der);
        $tbs = $parsed['children'][0];
        $tbsChildren = $tbs['children'];

        // Extract issuer and subject RDN sequences
        $issuerEncoded = $tbsChildren[3]['raw'];
        $subjectEncoded = $tbsChildren[5]['raw'];

        // Parse extensions
        $extensions = [];
        $isCA = false;
        $pathLen = null;
        $keyUsage = [];
        $extKeyUsage = [];
        $san = [];
        $ski = '';
        $aki = '';
        $cps = [];
        $aia = [];
        $cdp = [];

        // Extensions are in the last context-specific tag (tag 3)
        foreach ($tbsChildren as $child) {
            if (($child['tag'] & 0x1f) === 3) {
                $extSequence = $child['children'][0] ?? null;
                if ($extSequence) {
                    foreach ($extSequence['children'] ?? [] as $extChild) {
                        try {
                            $c = $extChild['children'] ?? [];
                            $extOid = $c[0]['oid'] ?? '';
                            $criticalIdx = (isset($c[1]) && $c[1]['tag'] === DER::TAG_BOOLEAN) ? 1 : -1;
                            $extCritical = $criticalIdx > 0;
                            $dataIdx = $criticalIdx > 0 ? 2 : 1;
                            $extData = $c[$dataIdx]['data'] ?? '';

                            if ($extOid === Extension::BASIC_CONSTRAINTS) {
                                $bc = Extension::decodeBasicConstraints(DER::parse($extData));
                                $isCA = $bc['ca'] ?? false;
                                $pathLen = $bc['pathLen'] ?? null;
                            } elseif ($extOid === Extension::KEY_USAGE) {
                                $keyUsage = Extension::decodeKeyUsage(DER::parse($extData));
                            } elseif ($extOid === Extension::EXTENDED_KEY_USAGE) {
                                $extKeyUsage = Extension::decodeExtendedKeyUsage(DER::parse($extData));
                            } elseif ($extOid === Extension::SUBJECT_ALT_NAME) {
                                $san = Extension::decodeGeneralNames(DER::parse($extData));
                            } elseif ($extOid === Extension::SUBJECT_KEY_IDENTIFIER) {
                                $ski = Extension::decodeSubjectKeyIdentifier(DER::parse($extData));
                            } elseif ($extOid === Extension::AUTHORITY_KEY_IDENTIFIER) {
                                $aki = Extension::decodeAuthorityKeyIdentifier(DER::parse($extData));
                            } elseif ($extOid === Extension::CERTIFICATE_POLICIES) {
                                $cps = Extension::decodeCertificatePolicies(DER::parse($extData));
                            } elseif ($extOid === Extension::AUTHORITY_INFO_ACCESS) {
                                $aia = Extension::decodeAccessDescriptions(DER::parse($extData));
                            } elseif ($extOid === Extension::CRL_DISTRIBUTION_POINTS) {
                                $cdp = Extension::decodeCRLDistributionPoints(DER::parse($extData));
                            }

                            $extensions[] = [
                                'oid' => $extOid,
                                'critical' => $extCritical,
                                'value' => $extData
                            ];
                        } catch (\Throwable) {}
                    }
                }
                break;
            }
        }

        // Parse SPKI for subject key identifier if not present
        if (!$ski) {
            try {
                $spki = $tbsChildren[6]['raw'];
                $ski = hex2bin(Hash::hash('sha1', $spki));
            } catch (\Throwable) {}
        }

        // Extract public key
        $subjectPK = $this->extractPublicKey($tbsChildren[6]);

        return [
            'der' => $der,
            'tbsDer' => $der,
            'serialNumber' => BigInt::fromBytes($tbsChildren[1]['data']),
            'issuer' => [
                'encoded' => $issuerEncoded,
                'rdn' => $this->decodeRDN($tbsChildren[3]),
                'der' => $tbsChildren[3]['raw'] ?? $der,
            ],
            'validity' => [
                'notBefore' => $tbsChildren[4]['children'][0]['data'] ?? '',
                'notAfter' => $tbsChildren[4]['children'][1]['data'] ?? '',
            ],
            'subject' => [
                'encoded' => $subjectEncoded,
                'rdn' => $this->decodeRDN($tbsChildren[5]),
                'der' => $tbsChildren[5]['raw'] ?? $der,
            ],
            'subjectPublicKeyInfo' => $subjectPK,
            'signatureAlgorithm' => $parsed['children'][1]['children'][0]['oid'] ?? '',
            'signatureValue' => $parsed['children'][2]['data'] ?? '',
            'basicConstraints' => ['ca' => $isCA, 'pathLen' => $pathLen],
            'keyUsage' => $keyUsage,
            'extendedKeyUsage' => $extKeyUsage,
            'subjectAltName' => $san,
            'subjectKeyIdentifier' => $ski,
            'authorityKeyIdentifier' => $aki,
            'certificatePolicies' => $cps,
            'authorityInfoAccess' => $aia,
            'crlDistributionPoints' => $cdp,
            'extensions' => $extensions,
        ];
    }

    private function extractPublicKey(array $spki): array {
        $alg = $spki['children'][0]['children'][0]['oid'] ?? '';
        $keyData = $spki['children'][1]['data'] ?? '';
        $keyBits = substr($keyData, 1); // skip unused bits byte

        return match ($alg) {
            '1.2.840.113549.1.1.1' => $this->parseRSAPublicKey($keyBits),
            '1.2.840.10045.2.1' => $this->parseECPublicKey($spki, $keyBits),
            default => ['algorithm' => $alg, 'keyData' => $keyBits],
        };
    }

    private function parseRSAPublicKey(string $keyBits): array {
        try {
            $parsed = DER::parse($keyBits);
            return [
                'algorithm' => 'rsa',
                'n' => BigInt::fromBytes($parsed['children'][0]['data']),
                'e' => BigInt::fromBytes($parsed['children'][1]['data']),
            ];
        } catch (\Throwable) {
            return ['algorithm' => 'rsa', 'keyBits' => $keyBits];
        }
    }

    private function parseECPublicKey(array $spki, string $keyBits): array {
        $curveOid = $spki['children'][0]['children'][1]['oid'] ?? '';
        return [
            'algorithm' => 'ec',
            'curveOid' => $curveOid,
            'point' => $keyBits,
        ];
    }

    private function encodeRDN(array $rdn): string {
        $children = [];
        foreach ($rdn as $key => $value) {
            $oid = $this->nameToOID($key);
            $strEnc = preg_match('/^[A-Za-z0-9 \'\(\)\+\,\-\.\/\:\=\?]+$/', $value) === 1
                ? DER::encodePrintableString($value)
                : DER::encodeUTF8String($value);
            $children[] = DER::encodeSet([DER::encodeSequence([DER::encodeOID($oid), $strEnc])]);
        }
        return DER::encodeSequence($children);
    }

    private function decodeRDN(array $rdnSeq): array {
        $result = [];
        $map = $this->oidToNameMap();
        foreach ($rdnSeq['children'] ?? [] as $set) {
            foreach ($set['children'] ?? [] as $seq) {
                $oid = $seq['children'][0]['oid'] ?? '';
                $value = $seq['children'][1]['data'] ?? '';
                $name = $map[$oid] ?? $oid;
                $result[$name] = $value;
            }
        }
        return $result;
    }

    private function nameToOID(string $name): string {
        $map = [
            'CN' => '2.5.4.3', 'commonName' => '2.5.4.3',
            'O' => '2.5.4.10', 'organizationName' => '2.5.4.10',
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
        return $map[$name] ?? $name;
    }

    private function oidToNameMap(): array {
        return [
            '2.5.4.3' => 'CN', '2.5.4.10' => 'O', '2.5.4.11' => 'OU',
            '2.5.4.7' => 'L', '2.5.4.8' => 'ST', '2.5.4.6' => 'C',
            '2.5.4.9' => 'STREET', '2.5.4.5' => 'SERIALNUMBER',
            '1.2.840.113549.1.9.1' => 'emailAddress',
            '0.9.2342.19200300.100.1.25' => 'DC',
            '0.9.2342.19200300.100.1.1' => 'UID',
        ];
    }

    public static function buildChain(array $cert, self $bundle): array {
        $chain = [$cert];
        $current = $cert;
        $visited = [];

        while (true) {
            $subjectKeyId = $current['subjectKeyIdentifier'] ?? '';
            $issuerKeyId = $current['authorityKeyIdentifier']['keyIdentifier'] ?? '';

            // Check if self-signed
            $subjectEncoded = $current['subject']['encoded'] ?? '';
            $issuerEncoded = $current['issuer']['encoded'] ?? '';
            if ($subjectEncoded === $issuerEncoded) {
                break; // reached root (self-signed)
            }

            // Try to find issuer in bundle
            $issuer = null;

            // Match by AKI/SKI first
            if ($issuerKeyId && $subjectKeyId !== $issuerKeyId) {
                foreach ($bundle->getCertificates() as $cand) {
                    $candSki = $cand['subjectKeyIdentifier'] ?? '';
                    if ($candSki && $candSki === $issuerKeyId) {
                        $issuer = $cand;
                        break;
                    }
                }
            }

            // Fall back to subject/issuer name matching
            if (!$issuer) {
                $issuer = $bundle->findByIssuerOf($current);
            }

            if (!$issuer) break;

            // Use DER hash for cycle detection (avoids spl_object_id on arrays)
            $certKey = md5($issuer['der'] ?? '');
            if (isset($visited[$certKey])) break;

            $visited[$certKey] = true;
            $chain[] = $issuer;
            $current = $issuer;
        }

        return $chain;
    }
}
