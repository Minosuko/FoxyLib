<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class FastHash {
    public static function fnv1(string $data): int {
        $hash = 0x811c9dc5;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash *= 0x01000193;
            $hash ^= ord($data[$i]);
            $hash &= 0xffffffff;
        }
        return $hash;
    }

    public static function fnv1a(string $data): int {
        $hash = 0x811c9dc5;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash ^= ord($data[$i]);
            $hash *= 0x01000193;
            $hash &= 0xffffffff;
        }
        return $hash;
    }

    public static function fnv164(string $data): int|float {
        $hash = 0xcbf29ce484222325;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash ^= ord($data[$i]);
            $hash *= 0x100000001b3;
            $hash &= 0xffffffffffffffff;
        }
        return $hash;
    }

    public static function fnv1a64(string $data): int|float {
        $hash = 0xcbf29ce484222325;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash *= 0x100000001b3;
            $hash ^= ord($data[$i]);
            $hash &= 0xffffffffffffffff;
        }
        return $hash;
    }

    public static function djb2(string $data): int {
        $hash = 5381;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash = (($hash << 5) + $hash) + ord($data[$i]);
            $hash &= 0xffffffff;
        }
        return $hash;
    }

    public static function sdbm(string $data): int {
        $hash = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash = (ord($data[$i]) + ($hash << 6) + ($hash << 16) - $hash) & 0xffffffff;
        }
        return $hash;
    }

    public static function jenkins(string $data): int {
        $hash = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $hash += ord($data[$i]);
            $hash += ($hash << 10);
            $hash ^= ($hash >> 6);
            $hash &= 0xffffffff;
        }
        $hash += ($hash << 3);
        $hash ^= ($hash >> 11);
        $hash += ($hash << 15);
        return $hash & 0xffffffff;
    }

    public static function pearson(string $data): string {
        $table = [];
        for ($i = 0; $i < 256; $i++) $table[$i] = ($i * 7 + 13) & 0xff;
        $hash = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $hash = $table[($hash ^ ord($data[$i])) & 0xff];
        }
        return chr($hash);
    }

    public static function crc8(string $data): int {
        $crc = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= ord($data[$i]);
            for ($j = 0; $j < 8; $j++) {
                $crc = ($crc & 1) ? (($crc >> 1) ^ 0x8c) : ($crc >> 1);
            }
        }
        return $crc & 0xff;
    }

    public static function crc16(string $data): int {
        $crc = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= ord($data[$i]);
            for ($j = 0; $j < 8; $j++) {
                $crc = ($crc & 1) ? (($crc >> 1) ^ 0xa001) : ($crc >> 1);
            }
        }
        return $crc & 0xffff;
    }

    public static function crc24(string $data): int {
        $crc = 0xb704ce;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= ord($data[$i]) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x1000000) $crc ^= 0x864cfb;
            }
            $crc &= 0xffffff;
        }
        return $crc & 0xffffff;
    }

    public static function crc32c(string $data): int {
        $crc = 0xffffffff;
        $table = [];
        for ($i = 0; $i < 256; $i++) {
            $c = $i;
            for ($j = 0; $j < 8; $j++) {
                $c = ($c & 1) ? (($c >> 1) ^ 0x82f63b78) : ($c >> 1);
            }
            $table[$i] = $c & 0xffffffff;
        }
        for ($i = 0; $i < strlen($data); $i++) {
            $crc = $table[($crc ^ ord($data[$i])) & 0xff] ^ ($crc >> 8);
            $crc &= 0xffffffff;
        }
        return ($crc ^ 0xffffffff) & 0xffffffff;
    }

    public static function crc32(string $data): int {
        $crc = 0xffffffff;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= ord($data[$i]);
            for ($j = 0; $j < 8; $j++) {
                $crc = ($crc & 1) ? (($crc >> 1) ^ 0xedb88320) : ($crc >> 1);
            }
        }
        return ($crc ^ 0xffffffff) & 0xffffffff;
    }

    public static function crc64(string $data): int|float {
        $crc = 0xffffffffffffffff;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= ord($data[$i]);
            for ($j = 0; $j < 8; $j++) {
                $crc = ($crc & 1) ? (($crc >> 1) ^ 0xc96c5795d7870f42) : ($crc >> 1);
                $crc &= 0xffffffffffffffff;
            }
        }
        return ($crc ^ 0xffffffffffffffff) & 0xffffffffffffffff;
    }

    public static function adler32(string $data): int {
        $a = 1; $b = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $a = ($a + ord($data[$i])) % 65521;
            $b = ($b + $a) % 65521;
        }
        return (($b << 16) | $a) & 0xffffffff;
    }

    public static function bsdm(string $data): int {
        $sum = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $sum = (($sum >> 1) | (($sum & 1) << 15)) & 0xffff;
            $sum = ($sum + ord($data[$i])) & 0xffff;
        }
        return $sum;
    }

    public static function sysv(string $data): int {
        $sum = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $sum = ($sum + ord($data[$i])) & 0xffff;
        }
        return $sum;
    }

    public static function xxhash32(string $data, int $seed = 0): int {
        $p1 = 0x9e3779b1; $p2 = 0x85ebca77; $p3 = 0xc2b2ae35; $p4 = 0x27d4eb2f;
        $p5 = 0x165667b1;
        $len = strlen($data);
        $h = $seed + $p5;
        $i = 0;
        if ($len >= 16) {
            $h1 = $seed + $p1 + $p2; $h2 = $seed + $p2; $h3 = $seed; $h4 = $seed - $p1;
            $limit = $len - 16;
            while ($i <= $limit) {
                $v = unpack('V', substr($data, $i, 4))[1];
                $h1 = self::xxh32round($h1, $v);
                $v = unpack('V', substr($data, $i+4, 4))[1];
                $h2 = self::xxh32round($h2, $v);
                $v = unpack('V', substr($data, $i+8, 4))[1];
                $h3 = self::xxh32round($h3, $v);
                $v = unpack('V', substr($data, $i+12, 4))[1];
                $h4 = self::xxh32round($h4, $v);
                $i += 16;
            }
            $h = self::rotl($h1, 1) + self::rotl($h2, 7) + self::rotl($h3, 12) + self::rotl($h4, 18);
        }
        $h += $len;
        while ($i + 4 <= $len) {
            $v = unpack('V', substr($data, $i, 4))[1];
            $h = self::xxh32round($h, $v);
            $i += 4;
        }
        while ($i < $len) {
            $h = self::rotl($h, 11) * $p3;
            $h = (($h ^ ord($data[$i])) & 0xffffffff);
            $i++;
        }
        $h ^= ($h >> 15); $h = ($h * $p2) & 0xffffffff;
        $h ^= ($h >> 13); $h = ($h * $p3) & 0xffffffff;
        $h ^= ($h >> 16);
        return $h;
    }

    private static function xxh32round($h, $v): int {
        $h = ($h + $v * 0x85ebca77) & 0xffffffff;
        $h = self::rotl($h, 13);
        $h = ($h * 0x9e3779b1) & 0xffffffff;
        return $h;
    }

    private static function rotl($x, $r): int { return (($x << $r) | ($x >> (32 - $r))) & 0xffffffff; }

    public static function murmur2(string $data, int $seed = 0): int {
        $len = strlen($data);
        $h = $seed ^ $len;
        $i = 0;
        $m = 0x5bd1e995;
        $r = 24;
        while ($i + 4 <= $len) {
            $k = unpack('V', substr($data, $i, 4))[1];
            $k = ($k * $m) & 0xffffffff;
            $k ^= ($k >> $r);
            $k = ($k * $m) & 0xffffffff;
            $h = ($h * $m) & 0xffffffff;
            $h ^= $k;
            $i += 4;
        }
        switch ($len - $i) {
            case 3: $h ^= ord($data[$i+2]) << 16;
            case 2: $h ^= ord($data[$i+1]) << 8;
            case 1: $h ^= ord($data[$i]);
                $h = ($h * $m) & 0xffffffff;
        }
        $h ^= ($h >> 13); $h = ($h * $m) & 0xffffffff;
        $h ^= ($h >> 15);
        return $h;
    }

    public static function murmur3(string $data, int $seed = 0): int {
        return self::murmur2($data, $seed); // simplified
    }
}
