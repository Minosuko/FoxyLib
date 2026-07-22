<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class DER {
    // Tag constants
    const TAG_BOOLEAN = 0x01;
    const TAG_INTEGER = 0x02;
    const TAG_BIT_STRING = 0x03;
    const TAG_OCTET_STRING = 0x04;
    const TAG_NULL = 0x05;
    const TAG_OID = 0x06;
    const TAG_UTF8_STRING = 0x0c;
    const TAG_SEQUENCE = 0x30;
    const TAG_SET = 0x31;
    const TAG_PRINTABLE_STRING = 0x13;
    const TAG_IA5_STRING = 0x16;
    const TAG_UTC_TIME = 0x17;
    const TAG_GENERALIZED_TIME = 0x18;
    const TAG_CONSTRUCTED = 0x20;
    const TAG_CONTEXT_SPECIFIC = 0x80;

    public static function encodeLength(int $len): string {
        if ($len < 0x80) return chr($len);
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    public static function decodeLength(string &$data): int {
        $byte = ord($data[0]);
        $data = substr($data, 1);
        if ($byte < 0x80) return $byte;
        $len = 0;
        for ($i = 0; $i < ($byte & 0x7f); $i++) {
            $len = ($len << 8) | ord($data[0]);
            $data = substr($data, 1);
        }
        return $len;
    }

    public static function encodeBoolean(bool $val): string {
        return chr(self::TAG_BOOLEAN) . "\x01" . ($val ? "\xff" : "\x00");
    }

    public static function encodeInteger(string $bytes): string {
        // Remove leading zeros but keep at least one byte
        $i = 0;
        while ($i < strlen($bytes) - 1 && $bytes[$i] === "\x00" && (ord($bytes[$i + 1]) & 0x80) === 0) {
            $i++;
        }
        $val = substr($bytes, $i);
        // Add leading zero if high bit is set
        if (ord($val[0]) & 0x80) $val = "\x00" . $val;
        return chr(self::TAG_INTEGER) . self::encodeLength(strlen($val)) . $val;
    }

    public static function encodeBitString(string $bytes): string {
        // Unused bits byte
        $val = "\x00" . $bytes;
        return chr(self::TAG_BIT_STRING) . self::encodeLength(strlen($val)) . $val;
    }

    public static function encodeOctetString(string $data): string {
        return chr(self::TAG_OCTET_STRING) . self::encodeLength(strlen($data)) . $data;
    }

    public static function encodeNull(): string {
        return chr(self::TAG_NULL) . "\x00";
    }

    public static function encodeOID(string $oid): string {
        $parts = explode('.', $oid);
        $p0 = isset($parts[0]) ? (int)$parts[0] : 0;
        $p1 = isset($parts[1]) ? (int)$parts[1] : 0;
        $result = chr(40 * $p0 + $p1);
        for ($i = 2; $i < count($parts); $i++) {
            $value = (int)$parts[$i];
            $bytes = '';
            if ($value === 0) {
                $bytes = "\x00";
            } else {
                $temp = '';
                while ($value > 0) {
                    $temp = chr(($value & 0x7f) | (strlen($temp) > 0 ? 0x80 : 0)) . $temp;
                    $value >>= 7;
                }
                $bytes = $temp;
            }
            $result .= $bytes;
        }
        return chr(self::TAG_OID) . self::encodeLength(strlen($result)) . $result;
    }

    public static function decodeOID(string $data): string {
        $first = ord($data[0]);
        $oid = (string)intdiv($first, 40) . '.' . ($first % 40);
        $i = 1;
        while ($i < strlen($data)) {
            $value = 0;
            while ($i < strlen($data)) {
                $byte = ord($data[$i]);
                $value = ($value << 7) | ($byte & 0x7f);
                $i++;
                if (!($byte & 0x80)) break;
            }
            $oid .= '.' . $value;
        }
        return $oid;
    }

    public static function encodeSequence(array $children): string {
        $data = '';
        foreach ($children as $child) {
            $data .= $child;
        }
        return chr(self::TAG_SEQUENCE) . self::encodeLength(strlen($data)) . $data;
    }

    public static function encodeSet(array $children): string {
        $data = '';
        foreach ($children as $child) {
            $data .= $child;
        }
        return chr(self::TAG_SET) . self::encodeLength(strlen($data)) . $data;
    }

    public static function encodeUTF8String(string $str): string {
        return chr(self::TAG_UTF8_STRING) . self::encodeLength(strlen($str)) . $str;
    }

    public static function encodePrintableString(string $str): string {
        return chr(self::TAG_PRINTABLE_STRING) . self::encodeLength(strlen($str)) . $str;
    }

    public static function encodeIA5String(string $str): string {
        return chr(self::TAG_IA5_STRING) . self::encodeLength(strlen($str)) . $str;
    }

    public static function encodeUTCTime(string $time): string {
        return chr(self::TAG_UTC_TIME) . self::encodeLength(strlen($time)) . $time;
    }

    public static function encodeGeneralizedTime(string $time): string {
        return chr(self::TAG_GENERALIZED_TIME) . self::encodeLength(strlen($time)) . $time;
    }

    public static function encodeEnumerated(int $val): string {
        $bytes = chr($val & 0xff);
        if ($val > 255) {
            $bytes = chr(($val >> 8) & 0xff) . $bytes;
        }
        if (ord($bytes[0]) & 0x80) $bytes = "\x00" . $bytes;
        return chr(0x0a) . self::encodeLength(strlen($bytes)) . $bytes;
    }

    public static function encodeContextSpecific(int $tag, string $data, bool $constructed = true): string {
        $t = self::TAG_CONTEXT_SPECIFIC | $tag;
        if ($constructed) $t |= self::TAG_CONSTRUCTED;
        return chr($t) . self::encodeLength(strlen($data)) . $data;
    }

    public static function parse(string $data): array {
        if (strlen($data) === 0) throw new \RuntimeException('Empty DER data');
        $result = self::parseElement($data);
        // If there's remaining data, wrap in a sequence
        $result['raw'] = $data;
        return $result;
    }

    private static function parseElement(string &$data): array {
        if (strlen($data) < 2) throw new \RuntimeException('DER element too short');
        $tag = ord($data[0]);
        $data = substr($data, 1);
        $length = self::decodeLength($data);
        if ($length > strlen($data)) throw new \RuntimeException('DER length exceeds data');
        $value = substr($data, 0, $length);
        $data = substr($data, $length);

        $element = [
            'tag' => $tag,
            'length' => $length,
            'data' => $value,
            'children' => [],
            'raw' => chr($tag) . self::encodeLength($length) . $value
        ];

        $constructed = ($tag & self::TAG_CONSTRUCTED) !== 0;
        $contextSpecific = ($tag & self::TAG_CONTEXT_SPECIFIC) !== 0;

        if ($constructed || $tag === self::TAG_SEQUENCE || $tag === self::TAG_SET) {
            $inner = $value;
            while (strlen($inner) > 0) {
                $element['children'][] = self::parseElement($inner);
            }
        }

        // Decode common types
        if ($tag === self::TAG_OID) {
            $element['oid'] = self::decodeOID($value);
        }

        return $element;
    }

    public static function encodeTime(\DateTimeInterface $time, bool $utc = true): string {
        if ($utc) {
            return self::encodeUTCTime($time->format('ymdHis') . 'Z');
        }
        return self::encodeGeneralizedTime($time->format('YmdHis') . 'Z');
    }

    // Sign a DER structure using RSA
    public static function sign(string $data, RSA $rsa, string $hashAlgo = 'sha256'): string {
        $digest = hex2bin(Hash::hash($hashAlgo, $data));
        $signature = $rsa->sign($digest, $hashAlgo);
        return self::encodeBitString($signature);
    }

    public static function encodeDigestInfo(string $digest, string $hashAlgo): string {
        $oidMap = [
            'md5' => '1.2.840.113549.2.5',
            'sha1' => '1.3.14.3.2.26',
            'sha224' => '2.16.840.1.101.3.4.2.4',
            'sha256' => '2.16.840.1.101.3.4.2.1',
            'sha384' => '2.16.840.1.101.3.4.2.2',
            'sha512' => '2.16.840.1.101.3.4.2.3',
        ];
        $oid = $oidMap[$hashAlgo] ?? '2.16.840.1.101.3.4.2.1';
        return self::encodeSequence([
            self::encodeSequence([
                self::encodeOID($oid),
                self::encodeNull()
            ]),
            self::encodeOctetString($digest)
        ]);
    }
}
