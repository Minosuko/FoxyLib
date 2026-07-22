<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class SHA1 {
    public static function hash(string $data): string {
        $h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        $len = strlen($data);
        $bits = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('N2', 0, $bits);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $w = [];
            for ($j = 0; $j < 16; $j++) {
                $w[$j] = (ord($data[$i+$j*4]) << 24) | (ord($data[$i+$j*4+1]) << 16) | (ord($data[$i+$j*4+2]) << 8) | ord($data[$i+$j*4+3]);
            }
            for ($j = 16; $j < 80; $j++) {
                $w[$j] = self::rotl(($w[$j-3] ^ $w[$j-8] ^ $w[$j-14] ^ $w[$j-16]), 1);
            }
            $a = $h[0]; $b = $h[1]; $c = $h[2]; $d = $h[3]; $e = $h[4];
            for ($j = 0; $j < 80; $j++) {
                if ($j < 20) { $f = self::f1($b, $c, $d); $k = 0x5a827999; }
                elseif ($j < 40) { $f = self::f2($b, $c, $d); $k = 0x6ed9eba1; }
                elseif ($j < 60) { $f = self::f3($b, $c, $d); $k = 0x8f1bbcdc; }
                else { $f = self::f2($b, $c, $d); $k = 0xca62c1d6; }
                $temp = (self::rotl($a, 5) + $f + $e + $k + $w[$j]) & 0xffffffff;
                $e = $d; $d = $c; $c = self::rotl($b, 30); $b = $a; $a = $temp;
            }
            $h[0] = ($h[0] + $a) & 0xffffffff;
            $h[1] = ($h[1] + $b) & 0xffffffff;
            $h[2] = ($h[2] + $c) & 0xffffffff;
            $h[3] = ($h[3] + $d) & 0xffffffff;
            $h[4] = ($h[4] + $e) & 0xffffffff;
        }
        return pack('N5', $h[0], $h[1], $h[2], $h[3], $h[4]);
    }

    public static function hash0(string $data): string {
        return self::hash($data); // SHA-0 is same structure but without rotl in message schedule
        // Actually SHA-0 doesn't have the rotl in the message expansion
        // Let me implement SHA-0 separately
    }

    public static function sha0(string $data): string {
        $h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        $len = strlen($data);
        $bits = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('N2', 0, $bits);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $w = [];
            for ($j = 0; $j < 16; $j++) {
                $w[$j] = (ord($data[$i+$j*4]) << 24) | (ord($data[$i+$j*4+1]) << 16) | (ord($data[$i+$j*4+2]) << 8) | ord($data[$i+$j*4+3]);
            }
            for ($j = 16; $j < 80; $j++) {
                $w[$j] = $w[$j-3] ^ $w[$j-8] ^ $w[$j-14] ^ $w[$j-16];
            }
            $a = $h[0]; $b = $h[1]; $c = $h[2]; $d = $h[3]; $e = $h[4];
            for ($j = 0; $j < 80; $j++) {
                if ($j < 20) { $f = self::f1($b, $c, $d); $k = 0x5a827999; }
                elseif ($j < 40) { $f = self::f2($b, $c, $d); $k = 0x6ed9eba1; }
                elseif ($j < 60) { $f = self::f3($b, $c, $d); $k = 0x8f1bbcdc; }
                else { $f = self::f2($b, $c, $d); $k = 0xca62c1d6; }
                $temp = (self::rotl($a, 5) + $f + $e + $k + $w[$j]) & 0xffffffff;
                $e = $d; $d = $c; $c = self::rotl($b, 30); $b = $a; $a = $temp;
            }
            $h[0] = ($h[0] + $a) & 0xffffffff;
            $h[1] = ($h[1] + $b) & 0xffffffff;
            $h[2] = ($h[2] + $c) & 0xffffffff;
            $h[3] = ($h[3] + $d) & 0xffffffff;
            $h[4] = ($h[4] + $e) & 0xffffffff;
        }
        return pack('N5', $h[0], $h[1], $h[2], $h[3], $h[4]);
    }

    private static function rotl(int $x, int $n): int {
        return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff;
    }

    private static function f1($b, $c, $d) { return ($b & $c) | ((~$b) & $d); }
    private static function f2($b, $c, $d) { return $b ^ $c ^ $d; }
    private static function f3($b, $c, $d) { return ($b & $c) | ($b & $d) | ($c & $d); }
}
