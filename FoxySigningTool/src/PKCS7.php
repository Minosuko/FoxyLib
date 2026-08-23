<?php
declare(strict_types=1);
namespace FoxySigningTool;

use FoxyCryptLib\{BigInt, DER, Hash, PEM, X509Certificate};

class PKCS7 {
    const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    const OID_DATA = '1.2.840.113549.1.7.1';
    const OID_RSA = '1.2.840.113549.1.1.1';
    const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
    const OID_RSA_SHA384 = '1.2.840.113549.1.1.12';
    const OID_RSA_SHA512 = '1.2.840.113549.1.1.13';
    const OID_ECDSA = '1.2.840.10045.2.1';
    const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
    const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
    const OID_ECDSA_SHA512 = '1.2.840.10045.4.3.4';
    const OID_DSA = '1.2.840.10040.4.1';
    const OID_DSA_SHA256 = '2.16.840.1.101.3.4.3.2';
    const OID_MD5 = '1.2.840.113549.2.5';
    const OID_SHA1 = '1.3.14.3.2.26';
    const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
    const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
    const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
    const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
    const OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6';

    const OID_SPC_INDIRECT_DATA_OBJID = '1.3.6.1.4.1.311.2.1.4';
    const OID_SPC_PE_IMAGE_DATAOBJ = '1.3.6.1.4.1.311.2.1.15';
    const OID_SPC_PE_IMAGE_PAGE_HASHES_V1 = '1.3.6.1.4.1.311.2.3.1';
    const OID_SPC_PE_IMAGE_PAGE_HASHES_V2 = '1.3.6.1.4.1.311.2.3.2';
    const OID_SPC_STATEMENT_TYPE = '1.3.6.1.4.1.311.2.1.11';
    const OID_SPC_SP_OPUS_INFO = '1.3.6.1.4.1.311.2.1.12';
    const OID_SPC_SP_OPUS_INFO_OPID = '1.3.6.1.4.1.311.2.1.21';
    const OID_SPC_CAB_DATA_OBJID = '1.3.6.1.4.1.311.2.1.10';
    const OID_SPC_JWT_OBJID = '1.3.6.1.4.1.311.2.1.17';
    const OID_SPC_SIPINFO_OBJID = '1.3.6.1.4.1.311.2.1.30';

    public static function buildSignedData(
        string $content,
        string $contentType,
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        ?array $extraCerts = [],
        ?string $contentDer = null,
        ?array $extraAttrs = [],
        bool $includeSignedAttrs = true,
        bool $rawContent = false,
        ?array $timestamp = null
    ): string {
        $hashOid = self::hashAlgoToOid($hashAlgo);
        $sigAlgoOid = self::getSignatureAlgoOid($signerKey, $hashAlgo);

        $digest = hex2bin(Hash::hash($hashAlgo, $content));

        if ($includeSignedAttrs) {
            $contentAttr = DER::encodeSequence([
                DER::encodeOID(self::OID_CONTENT_TYPE),
                DER::encodeSet([DER::encodeOID($contentType)])
            ]);

            $digestAttr = DER::encodeSequence([
                DER::encodeOID(self::OID_MESSAGE_DIGEST),
                DER::encodeSet([DER::encodeOctetString($digest)])
            ]);

            $attrList = array_merge([$contentAttr, $digestAttr], $extraAttrs);
            usort($attrList, static fn(string $a, string $b): int => strcmp($a, $b));

            $attrConcat = implode('', $attrList);
            $signedAttrs = DER::encodeContextSpecific(0, $attrConcat, true);

            // CMS signs the DER SET OF value, not the field's implicit [0] tag.
            $signedAttrsDigest = hex2bin(Hash::hash($hashAlgo, DER::encodeSet($attrList)));
            $sigValue = self::signDigest($signedAttrsDigest, $signerKey, $hashAlgo);
        } else {
            $signedAttrs = null;
            $sigValue = self::signDigest($digest, $signerKey, $hashAlgo);
        }

        $certInfo = X509Certificate::fromPEM($certPem);
        $issuerDer = $certInfo['issuer']['raw'];
        $serialDer = DER::encodeInteger($certInfo['serialNumber']->toBytes());
        $issuerAndSerial = DER::encodeSequence([$issuerDer, $serialDer]);

        $digestAlgorithms = DER::encodeSet([
            DER::encodeSequence([DER::encodeOID($hashOid), DER::encodeNull()])
        ]);

        if ($includeSignedAttrs) {
            $signerInfo = DER::encodeSequence([
                DER::encodeInteger("\x01"),
                $issuerAndSerial,
                DER::encodeSequence([DER::encodeOID($hashOid), DER::encodeNull()]),
                $signedAttrs,
                DER::encodeSequence([DER::encodeOID($sigAlgoOid), DER::encodeNull()]),
                DER::encodeOctetString($sigValue)
            ]);
        } else {
            $signerInfo = DER::encodeSequence([
                DER::encodeInteger("\x01"),
                $issuerAndSerial,
                DER::encodeSequence([DER::encodeOID($hashOid), DER::encodeNull()]),
                DER::encodeSequence([DER::encodeOID($sigAlgoOid), DER::encodeNull()]),
                DER::encodeOctetString($sigValue)
            ]);
        }

        $innerDer = $contentDer;
        if ($contentDer !== null && !$rawContent) {
            $innerDer = DER::encodeOctetString($contentDer);
        }
        if ($innerDer !== null) {
            $encapContentInfo = DER::encodeSequence([
                DER::encodeOID($contentType),
                DER::encodeContextSpecific(0, $innerDer, true)
            ]);
        } else {
            $encapContentInfo = DER::encodeSequence([DER::encodeOID($contentType)]);
        }

        $certDer = PEM::decode($certPem)['data'];
        $allCerts = [$certDer];
        if ($extraCerts) {
            foreach ($extraCerts as $ec) {
                $info = PEM::decode($ec);
                $allCerts[] = $info['data'];
            }
        }

        $certsSet = DER::encodeContextSpecific(0, implode('', $allCerts), true);

        $signedData = DER::encodeSequence([
            DER::encodeInteger("\x01"),
            $digestAlgorithms,
            $encapContentInfo,
            $certsSet,
            DER::encodeSet([$signerInfo])
        ]);

        $cms = DER::encodeSequence([
            DER::encodeOID(self::OID_SIGNED_DATA),
            DER::encodeContextSpecific(0, $signedData, true)
        ]);
        return self::applyTimestamp($cms, $hashAlgo, $timestamp);
    }

    public static function buildDetachedSignature(
        string $content,
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        ?array $timestamp = null
    ): string {
        return self::buildSignedData($content, self::OID_DATA, $signerKey, $certPem, $hashAlgo, $extraCerts, null, [], true, false, $timestamp);
    }

    public static function buildAuthenticodeSignature(
        string $peHash,
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        string $fileUrl = '',
        ?array $timestamp = null
    ): string {
        $hashOid = self::hashAlgoToOid($hashAlgo);

        $digestInfo = DER::encodeSequence([
            DER::encodeSequence([DER::encodeOID($hashOid), DER::encodeNull()]),
            DER::encodeOctetString($peHash)
        ]);

        $spcPeImageFlags = DER::encodeBitString('');
        $obsoleteFileLink = DER::encodeContextSpecific(
            0,
            DER::encodeContextSpecific(
                2,
                DER::encodeContextSpecific(0, '', false),
                true
            ),
            true
        );
        $spcPeImageData = DER::encodeSequence([
            $spcPeImageFlags,
            $obsoleteFileLink
        ]);

        $spcAttribute = DER::encodeSequence([
            DER::encodeOID(self::OID_SPC_PE_IMAGE_DATAOBJ),
            $spcPeImageData
        ]);

        $spcIndirectDataValue = $spcAttribute . $digestInfo;
        $spcIndirectData = DER::encodeSequence([$spcIndirectDataValue]);

        $attrList = [];

        return self::buildSignedData(
            $spcIndirectDataValue,
            self::OID_SPC_INDIRECT_DATA_OBJID,
            $signerKey,
            $certPem,
            $hashAlgo,
            $extraCerts,
            $spcIndirectData,
            $attrList,
            true,
            true,
            $timestamp
        );
    }

    public static function buildMSIAuthenticodeSignature(
        string $msiHash,
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        int $sipVersion = 1,
        ?array $timestamp = null
    ): string {
        if ($sipVersion !== 1 && $sipVersion !== 2) {
            throw new \InvalidArgumentException('MSI SIP version must be 1 or 2');
        }
        $hashOid = self::hashAlgoToOid($hashAlgo);
        $spcSipInfo = DER::encodeSequence([
            DER::encodeInteger(chr($sipVersion)),
            DER::encodeOctetString("\xF1\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"),
            DER::encodeInteger("\x00"),
            DER::encodeInteger("\x00"),
            DER::encodeInteger("\x00"),
            DER::encodeInteger("\x00"),
            DER::encodeInteger("\x00"),
        ]);
        $spcAttribute = DER::encodeSequence([
            DER::encodeOID(self::OID_SPC_SIPINFO_OBJID),
            $spcSipInfo,
        ]);
        $digestInfo = DER::encodeSequence([
            DER::encodeSequence([DER::encodeOID($hashOid), DER::encodeNull()]),
            DER::encodeOctetString($msiHash),
        ]);
        $spcIndirectDataValue = $spcAttribute . $digestInfo;
        $spcIndirectData = DER::encodeSequence([$spcIndirectDataValue]);
        $statementType = DER::encodeSequence([
            DER::encodeOID(self::OID_SPC_STATEMENT_TYPE),
            DER::encodeSet([
                DER::encodeSequence([DER::encodeOID(self::OID_SPC_SP_OPUS_INFO_OPID)]),
            ]),
        ]);

        return self::buildSignedData(
            $spcIndirectDataValue,
            self::OID_SPC_INDIRECT_DATA_OBJID,
            $signerKey,
            $certPem,
            $hashAlgo,
            $extraCerts,
            $spcIndirectData,
            [$statementType],
            true,
            true,
            $timestamp
        );
    }

    private static function applyTimestamp(string $cms, string $hashAlgo, ?array $timestamp): string {
        if ($timestamp === null) {
            return $cms;
        }
        $url = $timestamp['url'] ?? null;
        if (!is_string($url) || $url === '') {
            throw new \InvalidArgumentException('Timestamp URL must be a non-empty string');
        }
        $timeout = $timestamp['timeout'] ?? 15;
        if (!is_int($timeout)) {
            throw new \InvalidArgumentException('Timestamp timeout must be an integer');
        }
        $timestampHash = $timestamp['hash'] ?? $hashAlgo;
        if (!is_string($timestampHash)) {
            throw new \InvalidArgumentException('Timestamp hash must be a string');
        }
        $attributeOid = $timestamp['attributeOid'] ?? TimestampClient::OID_SIGNATURE_TIMESTAMP;
        if (!is_string($attributeOid)) {
            throw new \InvalidArgumentException('Timestamp attribute OID must be a string');
        }
        return (new TimestampClient($url, $timeout))->timestamp($cms, $timestampHash, $attributeOid);
    }

    private static function signDigest(string $digest, object $key, string $hashAlgo): string {
        if ($key instanceof \FoxyCryptLib\RSA) return $key->sign($digest, $hashAlgo);
        if ($key instanceof \FoxyCryptLib\ECDSA) return $key->sign($digest);
        if ($key instanceof \FoxyCryptLib\DSA) return $key->sign($digest);
        throw new \RuntimeException('Unsupported key type');
    }

    public static function hashAlgoToOid(string $algo): string {
        return match ($algo) {
            'md5' => self::OID_MD5,
            'sha1' => self::OID_SHA1,
            'sha256' => self::OID_SHA256,
            'sha384' => self::OID_SHA384,
            'sha512' => self::OID_SHA512,
            default => self::OID_SHA256,
        };
    }

    private static function getSignatureAlgoOid(object $key, string $hashAlgo): string {
        if ($key instanceof \FoxyCryptLib\RSA) {
            return match ($hashAlgo) {
                'sha256' => self::OID_RSA_SHA256,
                'sha384' => self::OID_RSA_SHA384,
                'sha512' => self::OID_RSA_SHA512,
                default => self::OID_RSA_SHA256,
            };
        }
        if ($key instanceof \FoxyCryptLib\ECDSA) {
            return match ($hashAlgo) {
                'sha256' => self::OID_ECDSA_SHA256,
                'sha384' => self::OID_ECDSA_SHA384,
                'sha512' => self::OID_ECDSA_SHA512,
                default => self::OID_ECDSA_SHA256,
            };
        }
        if ($key instanceof \FoxyCryptLib\DSA) return self::OID_DSA_SHA256;
        throw new \RuntimeException('Unsupported key type');
    }

    public static function parseSignedData(string $der): array {
        $outer = DER::parse($der);
        $signedData = $outer['children'][1]['children'][0];
        $certs = [];
        if (isset($signedData['children'][3]['children'])) {
            $certs = $signedData['children'][3]['children'];
        }
        return [
            'version' => $signedData['children'][0]['data'],
            'digestAlgorithms' => $signedData['children'][1]['children'],
            'encapContentInfo' => $signedData['children'][2]['children'][0]['oid'] ?? '',
            'certificates' => $certs,
            'signerInfos' => $signedData['children'][4]['children'] ?? [],
        ];
    }
}
