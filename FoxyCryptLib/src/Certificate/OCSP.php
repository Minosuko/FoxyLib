<?php
declare(strict_types=1);
namespace FoxyCryptLib\Certificate;

use FoxyCryptLib\{BigInt, DER, Hash};

class OCSP {
    const STATUS_SUCCESS = 0;
    const STATUS_MALFORMED = 1;
    const STATUS_INTERNAL = 2;
    const STATUS_TRY_LATER = 3;
    const STATUS_SIG_REQUIRED = 5;
    const STATUS_UNAUTHORIZED = 6;

    const CERT_GOOD = 0;
    const CERT_REVOKED = 1;
    const CERT_UNKNOWN = 2;

    const OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';

    public static function buildRequest(string $issuerNameDer, string $issuerKeyDer, string $serialBytes, ?string $nonce = null): string {
        $issuerNameHash = hex2bin(Hash::hash('sha1', $issuerNameDer));
        $issuerKeyHash = hex2bin(Hash::hash('sha1', $issuerKeyDer));

        $certId = DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID('1.3.14.3.2.26'),
                DER::encodeNull()
            ]),
            DER::encodeOctetString($issuerNameHash),
            DER::encodeOctetString($issuerKeyHash),
            DER::encodeInteger($serialBytes)
        ]);

        $tbsParts = [
            DER::encodeContextSpecific(0, DER::encodeInteger("\x00")),
            DER::encodeSequence([DER::encodeSequence([$certId])]),
        ];

        if ($nonce) {
            $nonceExt = (new Extension(Extension::OCSP_NONCE, false, $nonce))->encode();
            $tbsParts[] = DER::encodeContextSpecific(2, DER::encodeSequence([$nonceExt]));
        }

        return DER::encodeSequence([DER::encodeSequence($tbsParts)]);
    }

    public static function parseRequest(string $der): array {
        $parsed = DER::parse($der);
        $tbs = $parsed['children'][0] ?? [];
        $result = [
            'version' => 0,
            'requestList' => [],
            'extensions' => [],
        ];

        if (empty($tbs)) return $result;

        $childIdx = 0;
        $tbsChildren = $tbs['children'] ?? [];

        if (isset($tbsChildren[$childIdx]) && ($tbsChildren[$childIdx]['tag'] & 0x1f) === 0) {
            $result['version'] = (int)BigInt::fromBytes($tbsChildren[$childIdx]['children'][0]['data'])->toInt();
            $childIdx++;
        }

        if (isset($tbsChildren[$childIdx]) && ($tbsChildren[$childIdx]['tag'] & 0x1f) === 1) {
            $childIdx++;
        }

        if (isset($tbsChildren[$childIdx])) {
            foreach ($tbsChildren[$childIdx]['children'] ?? [] as $req) {
                $singleReq = ['certID' => []];
                $reqChildren = $req['children'] ?? [];
                $certIdChildren = $reqChildren[0]['children'] ?? [];
                if (count($certIdChildren) >= 4) {
                    $singleReq['certID'] = [
                        'hashAlgorithm' => $certIdChildren[0]['children'][0]['oid'] ?? '1.3.14.3.2.26',
                        'issuerNameHash' => $certIdChildren[1]['data'] ?? '',
                        'issuerKeyHash' => $certIdChildren[2]['data'] ?? '',
                        'serialNumber' => BigInt::fromBytes($certIdChildren[3]['data']),
                    ];
                }
                $result['requestList'][] = $singleReq;
            }
            $childIdx++;
        }

        if (isset($tbsChildren[$childIdx]) && ($tbsChildren[$childIdx]['tag'] & 0x1f) === 2) {
            $result['extensions'] = self::parseExtensions($tbsChildren[$childIdx]);
        }

        return $result;
    }

    public static function buildResponse(
        array $responses,
        string $responderNameDer,
        string $signature,
        string $signatureAlgoOid,
        ?array $certs = [],
        ?string $nonce = null,
        ?\DateTimeInterface $producedAt = null
    ): string {
        $producedAt = $producedAt ?? new \DateTimeImmutable();

        $singleResponses = [];
        foreach ($responses as $resp) {
            $certStatus = match ($resp['status']) {
                self::CERT_GOOD => DER::encodeContextSpecific(0, DER::encodeNull(), false),
                self::CERT_REVOKED => DER::encodeContextSpecific(1, DER::encodeSequence([
                    self::encodeTimeValue($resp['revocationTime'] ?? time()),
                    isset($resp['revocationReason'])
                        ? DER::encodeEnumerated($resp['revocationReason'])
                        : DER::encodeEnumerated(0)
                ]), true),
                default => DER::encodeContextSpecific(2, DER::encodeNull(), false),
            };

            $singleResponses[] = DER::encodeSequence([
                $resp['certId'],
                $certStatus,
                self::encodeTimeValue($producedAt->getTimestamp()),
            ]);
        }

        $rdParts = [
            DER::encodeContextSpecific(0, DER::encodeInteger("\x00")),
            DER::encodeContextSpecific(1, $responderNameDer, true),
            DER::encodeGeneralizedTime($producedAt->format('YmdHis') . 'Z'),
            DER::encodeSequence($singleResponses),
        ];

        if ($nonce) {
            $nonceExt = (new Extension(Extension::OCSP_NONCE, false, $nonce))->encode();
            $rdParts[] = DER::encodeContextSpecific(2, DER::encodeSequence([$nonceExt]));
        }

        $responseData = DER::encodeSequence($rdParts);

        $basicParts = [
            $responseData,
            DER::encodeSequence([
                DER::encodeOID($signatureAlgoOid),
                DER::encodeNull()
            ]),
            DER::encodeBitString($signature),
        ];

        if ($certs) {
            $basicParts[] = DER::encodeContextSpecific(0, DER::encodeSequence($certs), true);
        }

        $basicOcspResponse = DER::encodeSequence($basicParts);

        $responseBytes = DER::encodeSequence([
            DER::encodeOID(self::OCSP_BASIC),
            DER::encodeOctetString($basicOcspResponse)
        ]);

        return DER::encodeSequence([
            DER::encodeEnumerated(self::STATUS_SUCCESS),
            DER::encodeContextSpecific(0, $responseBytes, true)
        ]);
    }

    public static function parseResponse(string $der): array {
        $parsed = DER::parse($der);
        $result = [
            'responseStatus' => self::STATUS_SUCCESS,
            'responseType' => '',
            'responses' => [],
            'producedAt' => '',
            'signatureAlgorithm' => '',
            'signature' => '',
            'certs' => [],
        ];

        $result['responseStatus'] = ord($parsed['children'][0]['data'] ?? "\x00");
        if ($result['responseStatus'] !== self::STATUS_SUCCESS) return $result;

        $rbNode = $parsed['children'][1] ?? null;
        if (!$rbNode) return $result;

        $rbChildren = $rbNode['children'][0]['children'] ?? [];
        $result['responseType'] = $rbChildren[0]['oid'] ?? '';
        if ($result['responseType'] !== self::OCSP_BASIC) return $result;

        $basicDer = $rbChildren[1]['data'] ?? '';
        $basicParsed = DER::parse($basicDer);

        $rdNode = $basicParsed['children'][0];
        $rdChildren = $rdNode['children'] ?? [];

        $result['signatureAlgorithm'] = $basicParsed['children'][1]['children'][0]['oid'] ?? '';
        $sigRaw = $basicParsed['children'][2]['data'] ?? '';
        $result['signature'] = substr($sigRaw, 1);

        $idx = 0;
        if (isset($rdChildren[$idx]) && ($rdChildren[$idx]['tag'] & 0x1f) === 0) $idx++;
        if (isset($rdChildren[$idx]) && ($rdChildren[$idx]['tag'] & 0x1f) === 1) $idx++;

        $result['producedAt'] = $rdChildren[$idx]['data'] ?? '';
        $idx++;

        if (isset($rdChildren[$idx])) {
            foreach ($rdChildren[$idx]['children'] ?? [] as $single) {
                $status = self::CERT_UNKNOWN;
                $rTime = null;
                $rReason = null;

                $csNode = $single['children'][1] ?? null;
                if ($csNode) {
                    $tag = $csNode['tag'] & 0x1f;
                    $status = match ($tag) {
                        0 => self::CERT_GOOD,
                        1 => self::CERT_REVOKED,
                        default => self::CERT_UNKNOWN,
                    };
                    if ($tag === 1) {
                        $rTime = $csNode['children'][0]['data'] ?? null;
                        $rReason = isset($csNode['children'][1]) ? ord($csNode['children'][1]['data']) : null;
                    }
                }

                $result['responses'][] = [
                    'certId' => $single['children'][0] ?? [],
                    'certStatus' => $status,
                    'revocationTime' => $rTime,
                    'revocationReason' => $rReason,
                    'thisUpdate' => $single['children'][2]['data'] ?? '',
                ];
            }
        }

        if (isset($basicParsed['children'][3])) {
            $certsNode = $basicParsed['children'][3];
            foreach ($certsNode['children'] ?? [] as $cert) {
                $result['certs'][] = $cert['raw'] ?? $cert['data'] ?? '';
            }
        }

        return $result;
    }

    public static function buildCertId(string $issuerNameDer, string $issuerKeyDer, string $serialBytes, string $hashAlgo = 'sha1'): string {
        $issuerNameHash = hex2bin(Hash::hash($hashAlgo, $issuerNameDer));
        $issuerKeyHash = hex2bin(Hash::hash($hashAlgo, $issuerKeyDer));

        $hashOid = match ($hashAlgo) {
            'sha1' => '1.3.14.3.2.26',
            'sha256' => '2.16.840.1.101.3.4.2.1',
            'sha384' => '2.16.840.1.101.3.4.2.2',
            'sha512' => '2.16.840.1.101.3.4.2.3',
            default => '1.3.14.3.2.26',
        };

        return DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID($hashOid),
                DER::encodeNull()
            ]),
            DER::encodeOctetString($issuerNameHash),
            DER::encodeOctetString($issuerKeyHash),
            DER::encodeInteger($serialBytes)
        ]);
    }

    private static function parseExtensions(array $node): array {
        $exts = [];
        $seq = $node['children'][0] ?? $node;
        foreach ($seq['children'] ?? [] as $child) {
            $c = $child['children'] ?? [];
            $oid = $c[0]['oid'] ?? '';
            $critical = isset($c[1]) && $c[1]['tag'] === DER::TAG_BOOLEAN;
            $dataIdx = $critical ? 2 : 1;
            $data = $c[$dataIdx]['data'] ?? '';
            $exts[] = ['oid' => $oid, 'critical' => $critical, 'value' => Extension::decodeValue($oid, $data)];
        }
        return $exts;
    }

    private static function encodeTimeValue(int $timestamp): string {
        $dt = new \DateTimeImmutable("@$timestamp");
        return DER::encodeGeneralizedTime($dt->format('YmdHis') . 'Z');
    }
}
