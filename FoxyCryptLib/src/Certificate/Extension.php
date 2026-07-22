<?php
declare(strict_types=1);
namespace FoxyCryptLib\Certificate;

use FoxyCryptLib\{BigInt, DER};

class Extension {
    const BASIC_CONSTRAINTS = '2.5.29.19';
    const KEY_USAGE = '2.5.29.15';
    const EXTENDED_KEY_USAGE = '2.5.29.37';
    const SUBJECT_KEY_IDENTIFIER = '2.5.29.14';
    const AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';
    const SUBJECT_ALT_NAME = '2.5.29.17';
    const ISSUER_ALT_NAME = '2.5.29.18';
    const CRL_DISTRIBUTION_POINTS = '2.5.29.31';
    const AUTHORITY_INFO_ACCESS = '1.3.6.1.5.5.7.1.1';
    const SUBJECT_INFO_ACCESS = '1.3.6.1.5.5.7.1.11';
    const CERTIFICATE_POLICIES = '2.5.29.32';
    const POLICY_MAPPINGS = '2.5.29.33';
    const NAME_CONSTRAINTS = '2.5.29.30';
    const POLICY_CONSTRAINTS = '2.5.29.36';
    const INHIBIT_ANY_POLICY = '2.5.29.54';
    const TLS_FEATURE = '1.3.6.1.5.5.7.1.24';
    const SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
    const PRECERT_POISON = '1.3.6.1.4.1.11129.2.4.3';
    const CRL_NUMBER = '2.5.29.20';
    const INVALIDITY_DATE = '2.5.29.24';
    const REASON_CODE = '2.5.29.21';
    const OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
    const OCSP_RESPONSE = '1.3.6.1.5.5.7.48.1.1';

    public string $oid;
    public bool $critical;
    public mixed $value;

    public function __construct(string $oid, bool $critical, mixed $value) {
        $this->oid = $oid;
        $this->critical = $critical;
        $this->value = $value;
    }

    public function encode(): string {
        return DER::encodeSequence([
            DER::encodeOID($this->oid),
            $this->critical ? DER::encodeBoolean(true) : '',
            DER::encodeOctetString(self::encodeValue($this->oid, $this->value))
        ]);
    }

    public static function encodeValue(string $oid, mixed $value): string {
        return match ($oid) {
            self::BASIC_CONSTRAINTS => self::encodeBasicConstraints($value),
            self::KEY_USAGE => self::encodeKeyUsage($value),
            self::EXTENDED_KEY_USAGE => self::encodeExtendedKeyUsage($value),
            self::SUBJECT_KEY_IDENTIFIER => DER::encodeOctetString($value),
            self::AUTHORITY_KEY_IDENTIFIER => self::encodeAuthorityKeyIdentifier($value),
            self::SUBJECT_ALT_NAME, self::ISSUER_ALT_NAME => self::encodeGeneralNames($value),
            self::CRL_DISTRIBUTION_POINTS => self::encodeCRLDistributionPoints($value),
            self::AUTHORITY_INFO_ACCESS, self::SUBJECT_INFO_ACCESS => self::encodeAccessDescriptions($value),
            self::CERTIFICATE_POLICIES => self::encodeCertificatePolicies($value),
            self::POLICY_MAPPINGS => self::encodePolicyMappings($value),
            self::NAME_CONSTRAINTS => self::encodeNameConstraints($value),
            self::POLICY_CONSTRAINTS => self::encodePolicyConstraints($value),
            self::INHIBIT_ANY_POLICY => self::encodeInhibitAnyPolicy($value),
            self::TLS_FEATURE => self::encodeTLSFeature($value),
            self::SCT_LIST => DER::encodeOctetString($value),
            self::PRECERT_POISON => DER::encodeNull(),
            self::CRL_NUMBER => DER::encodeInteger($value),
            self::INVALIDITY_DATE => self::encodeTimeValue($value),
            self::REASON_CODE => DER::encodeEnumerated($value),
            self::OCSP_NONCE => DER::encodeOctetString($value),
            default => $value instanceof \Stringable || is_string($value) ? (string)$value : throw new \InvalidArgumentException("Unknown extension OID: $oid"),
        };
    }

    public static function decodeValue(string $oid, string $octetData): mixed {
        $parsed = DER::parse($octetData);
        return match ($oid) {
            self::BASIC_CONSTRAINTS => self::decodeBasicConstraints($parsed),
            self::KEY_USAGE => self::decodeKeyUsage($parsed),
            self::EXTENDED_KEY_USAGE => self::decodeExtendedKeyUsage($parsed),
            self::SUBJECT_KEY_IDENTIFIER => self::decodeSubjectKeyIdentifier($parsed),
            self::AUTHORITY_KEY_IDENTIFIER => self::decodeAuthorityKeyIdentifier($parsed),
            self::SUBJECT_ALT_NAME, self::ISSUER_ALT_NAME => self::decodeGeneralNames($parsed),
            self::CRL_DISTRIBUTION_POINTS => self::decodeCRLDistributionPoints($parsed),
            self::AUTHORITY_INFO_ACCESS, self::SUBJECT_INFO_ACCESS => self::decodeAccessDescriptions($parsed),
            self::CERTIFICATE_POLICIES => self::decodeCertificatePolicies($parsed),
            self::POLICY_MAPPINGS => self::decodePolicyMappings($parsed),
            self::NAME_CONSTRAINTS => self::decodeNameConstraints($parsed),
            self::POLICY_CONSTRAINTS => self::decodePolicyConstraints($parsed),
            self::INHIBIT_ANY_POLICY => ord($parsed['data']),
            self::TLS_FEATURE => self::decodeTLSFeature($parsed),
            self::SCT_LIST => $octetData,
            self::PRECERT_POISON => true,
            self::CRL_NUMBER => BigInt::fromBytes($parsed['data'])->toInt(),
            self::INVALIDITY_DATE => self::decodeTimeValue($parsed),
            self::REASON_CODE => ord($parsed['data']),
            self::OCSP_NONCE => $parsed['data'],
            default => $octetData,
        };
    }

    // --- Basic Constraints ---
    public static function encodeBasicConstraints(array $value): string {
        $children = [];
        if (!empty($value['ca'])) {
            $children[] = DER::encodeBoolean(true);
        }
        if (isset($value['pathLen'])) {
            $children[] = DER::encodeInteger(chr($value['pathLen']));
        }
        return DER::encodeSequence($children);
    }

    public static function decodeBasicConstraints(array $parsed): array {
        $result = ['ca' => false];
        $children = $parsed['children'] ?? [];
        if (isset($children[0])) {
            $result['ca'] = $children[0]['tag'] === DER::TAG_BOOLEAN && ord($children[0]['data']) !== 0;
        }
        if (isset($children[1]) && $children[1]['tag'] === DER::TAG_INTEGER) {
            $result['pathLen'] = (int)BigInt::fromBytes($children[1]['data'])->toInt();
        }
        return $result;
    }

    // --- Key Usage ---
    const KU_DIGITAL_SIGNATURE = 0x80;
    const KU_NON_REPUDIATION = 0x40;
    const KU_KEY_ENCIPHERMENT = 0x20;
    const KU_DATA_ENCIPHERMENT = 0x10;
    const KU_KEY_AGREEMENT = 0x08;
    const KU_KEY_CERT_SIGN = 0x04;
    const KU_CRL_SIGN = 0x02;
    const KU_ENCIPHER_ONLY = 0x01;
    const KU_DECIPHER_ONLY = 0x8000;

    public static function encodeKeyUsage(array $bits): string {
        $bytes = '';
        $acc = 0;
        foreach ($bits as $i => $bit) {
            if ($bit) {
                $bytePos = intdiv($i, 8);
                $bitPos = 7 - ($i % 8);
                while (strlen($bytes) <= $bytePos) $bytes .= "\x00";
                $bytes[$bytePos] = chr(ord($bytes[$bytePos]) | (1 << $bitPos));
            }
        }
        return DER::encodeBitString(rtrim($bytes, "\x00") ?: "\x00");
    }

    public static function decodeKeyUsage(array $parsed): array {
        $data = $parsed['data'];
        $unusedBits = ord($data[0]);
        $bits = substr($data, 1);
        $result = [];
        $totalBits = strlen($bits) * 8 - $unusedBits;
        for ($i = 0; $i < $totalBits; $i++) {
            $bytePos = intdiv($i, 8);
            $bitPos = 7 - ($i % 8);
            $result[] = (ord($bits[$bytePos]) >> $bitPos) & 1;
        }
        return $result;
    }

    // --- Extended Key Usage ---
    const EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    const EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
    const EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
    const EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';
    const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
    const EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
    const EKU_DVCS = '1.3.6.1.5.5.7.3.10';
    const EKU_IPSEC_END_SYSTEM = '1.3.6.1.5.5.7.3.5';
    const EKU_IPSEC_TUNNEL = '1.3.6.1.5.5.7.3.6';
    const EKU_IPSEC_USER = '1.3.6.1.5.5.7.3.7';
    const EKU_DOCUMENT_SIGNING = '1.3.6.1.5.5.7.3.12';

    public static function encodeExtendedKeyUsage(array $oids): string {
        $children = [];
        foreach ($oids as $oid) {
            $children[] = DER::encodeOID($oid);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeExtendedKeyUsage(array $parsed): array {
        $oids = [];
        foreach ($parsed['children'] ?? [] as $child) {
            if (isset($child['oid'])) $oids[] = $child['oid'];
        }
        return $oids;
    }

    // --- Authority Key Identifier ---
    public static function encodeAuthorityKeyIdentifier(array $value): string {
        $children = [];
        if (isset($value['keyIdentifier'])) {
            $children[] = DER::encodeContextSpecific(0, DER::encodeOctetString($value['keyIdentifier']), false);
        }
        if (isset($value['authorityCertIssuer'])) {
            $children[] = DER::encodeContextSpecific(1, self::encodeGeneralNames($value['authorityCertIssuer']), true);
        }
        if (isset($value['authorityCertSerialNumber'])) {
            $children[] = DER::encodeContextSpecific(2, DER::encodeInteger($value['authorityCertSerialNumber']), false);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeAuthorityKeyIdentifier(array $parsed): array {
        $result = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $tag = $child['tag'] & 0x1f;
            if ($tag === 0) {
                $inner = DER::parse($child['data']);
                $result['keyIdentifier'] = $inner['data'];
            } elseif ($tag === 1) {
                $result['authorityCertIssuer'] = self::decodeGeneralNames($child);
            } elseif ($tag === 2) {
                $result['authorityCertSerialNumber'] = $child['data'];
            }
        }
        return $result;
    }

    // --- Subject Key Identifier ---
    public static function decodeSubjectKeyIdentifier(array $parsed): string {
        return $parsed['data'];
    }

    // --- General Names (SAN, IAN) ---
    const GN_OTHER_NAME = 0;
    const GN_RFC822_NAME = 1;
    const GN_DNS_NAME = 2;
    const GN_X400_ADDRESS = 3;
    const GN_DIRECTORY_NAME = 4;
    const GN_EDI_PARTY_NAME = 5;
    const GN_URI = 6;
    const GN_IP_ADDRESS = 7;
    const GN_REGISTERED_ID = 8;

    public static function encodeGeneralNames(array $names): string {
        $children = [];
        foreach ($names as $name) {
            [$tag, $value] = $name;
            $encodedTag = DER::TAG_CONTEXT_SPECIFIC | $tag;
            if ($tag === self::GN_DIRECTORY_NAME) {
                $encodedTag |= DER::TAG_CONSTRUCTED;
                $children[] = chr($encodedTag) . DER::encodeLength(strlen($value)) . $value;
            } elseif ($tag === self::GN_OTHER_NAME) {
                $encodedTag |= DER::TAG_CONSTRUCTED;
                $children[] = chr($encodedTag) . DER::encodeLength(strlen($value)) . $value;
            } elseif ($tag === self::GN_RFC822_NAME) {
                $children[] = chr($encodedTag) . DER::encodeLength(strlen($value)) . $value;
            } else {
                $children[] = chr($encodedTag) . DER::encodeLength(strlen($value)) . $value;
            }
        }
        return DER::encodeSequence($children);
    }

    public static function decodeGeneralNames(array $parsed): array {
        $names = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $tag = $child['tag'] & 0x1f;
            $data = $child['data'];
            $names[] = [$tag, $data];
        }
        return $names;
    }

    // --- CRL Distribution Points ---
    public static function encodeCRLDistributionPoints(array $points): string {
        $children = [];
        foreach ($points as $point) {
            $dpChildren = [];
            if (isset($point['fullName'])) {
                $gn = self::encodeGeneralNames($point['fullName']);
                $dpChildren[] = DER::encodeContextSpecific(0, $gn, true);
            }
            if (isset($point['reasons'])) {
                $dpChildren[] = DER::encodeContextSpecific(1, DER::encodeBitString(chr($point['reasons'])), false);
            }
            if (isset($point['crlIssuer'])) {
                $gn = self::encodeGeneralNames($point['crlIssuer']);
                $dpChildren[] = DER::encodeContextSpecific(2, $gn, true);
            }
            $children[] = DER::encodeSequence($dpChildren);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeCRLDistributionPoints(array $parsed): array {
        $points = [];
        foreach ($parsed['children'] ?? [] as $dp) {
            $point = [];
            foreach ($dp['children'] ?? [] as $child) {
                $tag = $child['tag'] & 0x1f;
                if ($tag === 0) $point['fullName'] = self::decodeGeneralNames($child);
                elseif ($tag === 1) $point['reasons'] = ord($child['data'][1] ?? "\x00");
                elseif ($tag === 2) $point['crlIssuer'] = self::decodeGeneralNames($child);
            }
            $points[] = $point;
        }
        return $points;
    }

    // --- Authority Info Access / Subject Info Access ---
    const ACCESS_METHOD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';
    const ACCESS_METHOD_OCSP = '1.3.6.1.5.5.7.48.1';
    const ACCESS_METHOD_TIME_STAMPING = '1.3.6.1.5.5.7.48.3';
    const ACCESS_METHOD_CA_REPOSITORY = '1.3.6.1.5.5.7.48.5';

    public static function encodeAccessDescriptions(array $descs): string {
        $children = [];
        foreach ($descs as $desc) {
            $method = $desc[0];
            $location = $desc[1]; // [$tag, $value]
            $locDer = self::encodeGeneralName($location);
            $children[] = DER::encodeSequence([
                DER::encodeOID($method),
                $locDer
            ]);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeAccessDescriptions(array $parsed): array {
        $descs = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $method = $child['children'][0]['oid'] ?? '';
            $loc = self::decodeGeneralName($child['children'][1]);
            $descs[] = [$method, $loc];
        }
        return $descs;
    }

    // --- Certificate Policies ---
    public static function encodeCertificatePolicies(array $policies): string {
        $children = [];
        foreach ($policies as $policy) {
            $policyChildren = [DER::encodeOID($policy['oid'])];
            if (!empty($policy['qualifiers'])) {
                $qualifiers = [];
                foreach ($policy['qualifiers'] as $q) {
                    if ($q['type'] === 'cps') {
                        $qualifiers[] = DER::encodeSequence([
                            DER::encodeOID('1.3.6.1.5.5.7.2.1'),
                            DER::encodeIA5String($q['value'])
                        ]);
                    } elseif ($q['type'] === 'unotice') {
                        $noticeChildren = [];
                        if (isset($q['explicitText'])) {
                            $noticeChildren[] = DER::encodeContextSpecific(0, DER::encodeUTF8String($q['explicitText']), false);
                        }
                        if (isset($q['noticeNumbers'])) {
                            $nums = '';
                            foreach ($q['noticeNumbers'] as $num) {
                                $nums .= DER::encodeInteger(chr($num));
                            }
                            $noticeChildren[] = DER::encodeContextSpecific(1, DER::encodeSequence(explode('', $nums)), false);
                        }
                        $qualifiers[] = DER::encodeSequence([
                            DER::encodeOID('1.3.6.1.5.5.7.2.2'),
                            $noticeChildren ? DER::encodeSequence($noticeChildren) : DER::encodeSequence([])
                        ]);
                    }
                }
                if ($qualifiers) {
                    $policyChildren[] = DER::encodeSequence($qualifiers);
                }
            }
            $children[] = DER::encodeSequence($policyChildren);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeCertificatePolicies(array $parsed): array {
        $policies = [];
        foreach ($parsed['children'] ?? [] as $policy) {
            $p = ['oid' => $policy['children'][0]['oid'] ?? '', 'qualifiers' => []];
            if (isset($policy['children'][1])) {
                foreach ($policy['children'][1]['children'] ?? [] as $q) {
                    $qOid = $q['children'][0]['oid'] ?? '';
                    $qVal = $q['children'][1] ?? [];
                    if ($qOid === '1.3.6.1.5.5.7.2.1') {
                        $p['qualifiers'][] = ['type' => 'cps', 'value' => $qVal['data'] ?? ''];
                    } elseif ($qOid === '1.3.6.1.5.5.7.2.2') {
                        $p['qualifiers'][] = ['type' => 'unotice', 'value' => $qVal];
                    }
                }
            }
            $policies[] = $p;
        }
        return $policies;
    }

    // --- Policy Mappings ---
    public static function encodePolicyMappings(array $mappings): string {
        $children = [];
        foreach ($mappings as $m) {
            $children[] = DER::encodeSequence([
                DER::encodeOID($m['issuerDomain']),
                DER::encodeOID($m['subjectDomain'])
            ]);
        }
        return DER::encodeSequence($children);
    }

    public static function decodePolicyMappings(array $parsed): array {
        $mappings = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $mappings[] = [
                'issuerDomain' => $child['children'][0]['oid'] ?? '',
                'subjectDomain' => $child['children'][1]['oid'] ?? ''
            ];
        }
        return $mappings;
    }

    // --- Name Constraints ---
    public static function encodeNameConstraints(array $value): string {
        $children = [];
        if (!empty($value['permitted'])) {
            $children[] = DER::encodeContextSpecific(0, self::encodeGeneralNames($value['permitted']), true);
        }
        if (!empty($value['excluded'])) {
            $children[] = DER::encodeContextSpecific(1, self::encodeGeneralNames($value['excluded']), true);
        }
        return DER::encodeSequence($children);
    }

    public static function decodeNameConstraints(array $parsed): array {
        $result = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $tag = $child['tag'] & 0x1f;
            if ($tag === 0) $result['permitted'] = self::decodeGeneralNames($child);
            elseif ($tag === 1) $result['excluded'] = self::decodeGeneralNames($child);
        }
        return $result;
    }

    // --- Policy Constraints ---
    public static function encodePolicyConstraints(array $value): string {
        $children = [];
        if (isset($value['requireExplicitPolicy'])) {
            $children[] = DER::encodeContextSpecific(0, DER::encodeInteger(chr($value['requireExplicitPolicy'])), false);
        }
        if (isset($value['inhibitPolicyMapping'])) {
            $children[] = DER::encodeContextSpecific(1, DER::encodeInteger(chr($value['inhibitPolicyMapping'])), false);
        }
        return DER::encodeSequence($children);
    }

    public static function decodePolicyConstraints(array $parsed): array {
        $result = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $tag = $child['tag'] & 0x1f;
            if ($tag === 0) $result['requireExplicitPolicy'] = (int)BigInt::fromBytes($child['data'])->toInt();
            elseif ($tag === 1) $result['inhibitPolicyMapping'] = (int)BigInt::fromBytes($child['data'])->toInt();
        }
        return $result;
    }

    // --- Inhibit Any Policy ---
    public static function encodeInhibitAnyPolicy(int $skipCerts): string {
        return DER::encodeInteger(chr($skipCerts));
    }

    // --- TLS Feature (Must-Staple) ---
    const TLS_STATUS_REQUEST = 5;
    const TLS_STATUS_REQUEST_V2 = 17;

    public static function encodeTLSFeature(array $features): string {
        $children = [];
        foreach ($features as $f) {
            $children[] = DER::encodeInteger(chr($f));
        }
        return DER::encodeSequence($children);
    }

    public static function decodeTLSFeature(array $parsed): array {
        $features = [];
        foreach ($parsed['children'] ?? [] as $child) {
            $features[] = (int)BigInt::fromBytes($child['data'])->toInt();
        }
        return $features;
    }

    // --- Time value helpers ---
    private static function encodeTimeValue(int $timestamp): string {
        $dt = new \DateTimeImmutable("@$timestamp");
        return DER::encodeGeneralizedTime($dt->format('YmdHis') . 'Z');
    }

    private static function decodeTimeValue(array $parsed): int {
        $timeStr = $parsed['data'];
        return (new \DateTimeImmutable($timeStr))->getTimestamp() ?: 0;
    }

    // --- High-level helper for common extension patterns ---
    public static function makeBasicConstraints(bool $ca = false, ?int $pathLen = null): self {
        $val = ['ca' => $ca];
        if ($pathLen !== null) $val['pathLen'] = $pathLen;
        return new self(self::BASIC_CONSTRAINTS, $ca, $val);
    }

    public static function makeKeyUsage(array $bitFlags): self {
        return new self(self::KEY_USAGE, true, $bitFlags);
    }

    public static function makeExtendedKeyUsage(array $oids, bool $critical = false): self {
        return new self(self::EXTENDED_KEY_USAGE, $critical, $oids);
    }

    public static function makeSubjectKeyIdentifier(string $keyId): self {
        return new self(self::SUBJECT_KEY_IDENTIFIER, false, $keyId);
    }

    public static function makeAuthorityKeyIdentifier(string $keyId): self {
        return new self(self::AUTHORITY_KEY_IDENTIFIER, false, ['keyIdentifier' => $keyId]);
    }

    public static function makeSubjectAlternativeName(array $names): self {
        return new self(self::SUBJECT_ALT_NAME, false, $names);
    }

    public static function makeIssuerAlternativeName(array $names): self {
        return new self(self::ISSUER_ALT_NAME, false, $names);
    }

    public static function makeCRLDistributionPoints(array $points): self {
        return new self(self::CRL_DISTRIBUTION_POINTS, false, $points);
    }

    public static function makeAuthorityInfoAccess(array $descs): self {
        return new self(self::AUTHORITY_INFO_ACCESS, false, $descs);
    }

    public static function makeCertificatePolicies(array $policies): self {
        return new self(self::CERTIFICATE_POLICIES, false, $policies);
    }

    public static function makeTLSFeature(array $features): self {
        return new self(self::TLS_FEATURE, false, $features);
    }

    public static function makeSCTList(string $sctData): self {
        return new self(self::SCT_LIST, false, $sctData);
    }

    public static function makePrecertPoison(): self {
        return new self(self::PRECERT_POISON, true, true);
    }

    public static function makeNameConstraints(array $permitted = [], array $excluded = []): self {
        $val = [];
        if ($permitted) $val['permitted'] = $permitted;
        if ($excluded) $val['excluded'] = $excluded;
        return new self(self::NAME_CONSTRAINTS, true, $val);
    }

    public static function makePolicyConstraints(?int $requireExplicitPolicy = null, ?int $inhibitPolicyMapping = null): self {
        $val = [];
        if ($requireExplicitPolicy !== null) $val['requireExplicitPolicy'] = $requireExplicitPolicy;
        if ($inhibitPolicyMapping !== null) $val['inhibitPolicyMapping'] = $inhibitPolicyMapping;
        return new self(self::POLICY_CONSTRAINTS, true, $val);
    }

    // --- DNS Name shortcut ---
    // --- Single GeneralName encode/decode (for AIA/SIA where it's a CHOICE, not SEQUENCE) ---
    public static function encodeGeneralName(array $name): string {
        [$tag, $value] = $name;
        $encodedTag = DER::TAG_CONTEXT_SPECIFIC | $tag;
        if ($tag === self::GN_DIRECTORY_NAME || $tag === self::GN_OTHER_NAME) {
            $encodedTag |= DER::TAG_CONSTRUCTED;
        }
        return chr($encodedTag) . DER::encodeLength(strlen($value)) . $value;
    }

    public static function decodeGeneralName(array $parsed): array {
        $tag = $parsed['tag'] & 0x1f;
        return [$tag, $parsed['data']];
    }

    public static function dnsName(string $dns): array {
        return [self::GN_DNS_NAME, $dns];
    }

    public static function ipAddress(string $ip): array {
        return [self::GN_IP_ADDRESS, inet_pton($ip)];
    }

    public static function uri(string $uri): array {
        return [self::GN_URI, $uri];
    }

    public static function rfc822Name(string $email): array {
        return [self::GN_RFC822_NAME, $email];
    }

    public static function directoryName(string $derEncodedName): array {
        return [self::GN_DIRECTORY_NAME, $derEncodedName];
    }

    // --- AIA description shortcuts ---
    public static function caIssuer(string $url): array {
        return [self::ACCESS_METHOD_CA_ISSUERS, [self::GN_URI, $url]];
    }

    public static function ocspResponder(string $url): array {
        return [self::ACCESS_METHOD_OCSP, [self::GN_URI, $url]];
    }

    // --- CRL Distribution Point shortcut ---
    public static function crlPoint(string $url): array {
        return ['fullName' => [[self::GN_URI, $url]]];
    }
}
