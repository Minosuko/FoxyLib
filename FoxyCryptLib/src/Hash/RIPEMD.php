<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class RIPEMD {
    private const K0 = 0x00000000; private const K1 = 0x5a827999; private const K2 = 0x6ed9eba1;
    private const K3 = 0x00000000; private const K4 = 0x5a827999; private const K5 = 0x6ed9eba1;
    private const K6 = 0x50a28be6; private const K7 = 0x5c4dd124; private const K8 = 0x6d703ef3;
    private const K9 = 0x00000000;

    private static function rotl(int $x, int $n): int { return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff; }
    private static function add(int $a, int $b = 0, int $c = 0, int $d = 0): int { return ($a + $b + $c + $d) & 0xffffffff; }

    public static function hash160(string $data): string {
        $h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        $len = strlen($data);
        $bitLen = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('V', $bitLen) . str_repeat("\x00", 4);
        $r = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
        $sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
        $sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
        $rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
        for ($i = 0; $i < strlen($data); $i += 64) {
            $block = substr($data, $i, 64);
            $x = array_values(unpack('V16', $block));
            $a1 = $h[0]; $b1 = $h[1]; $c1 = $h[2]; $d1 = $h[3]; $e1 = $h[4];
            $a2 = $h[0]; $b2 = $h[1]; $c2 = $h[2]; $d2 = $h[3]; $e2 = $h[4];
            for ($j = 0; $j < 80; $j++) {
                $t = self::add(self::rotl(self::add($a1, self::f($j, $b1, $c1, $d1), $x[$r[$j]], self::k($j)), $sl[$j]), $e1);
                $a1 = $e1; $e1 = $d1; $d1 = self::rotl($c1, 10); $c1 = $b1; $b1 = $t;
                $t = self::add(self::rotl(self::add($a2, self::f(79-$j, $b2, $c2, $d2), $x[$rr[$j]], self::k(79-$j)), $sr[$j]), $e2);
                $a2 = $e2; $e2 = $d2; $d2 = self::rotl($c2, 10); $c2 = $b2; $b2 = $t;
            }
            $tb = $h[1] + $c1 + $d2;
            $h[1] = $h[2] + $d1 + $e2;
            $h[2] = $h[3] + $e1 + $a2;
            $h[3] = $h[4] + $a1 + $b2;
            $h[4] = $h[0] + $b1 + $c2;
            $h[0] = $tb;
        }
        return pack('V5', $h[0], $h[1], $h[2], $h[3], $h[4]);
    }

    public static function hash128(string $data): string {
        return substr(self::hash160($data), 0, 16);
    }

    public static function hash256(string $data): string {
        $h = self::hash160($data);
        return $h . self::hash160($h); // simplified: double hash for longer output
    }

    public static function hash320(string $data): string {
        $h = self::hash160($data);
        return $h . self::hash160(self::hash160($data));
    }

    private static function f(int $j, $x, $y, $z) {
        if ($j < 16) return $x ^ $y ^ $z;
        if ($j < 32) return ($x & $y) | ((~$x) & $z);
        if ($j < 48) return ($x | (~$y)) ^ $z;
        if ($j < 64) return ($x & $z) | ($y & (~$z));
        return $x ^ ($y | (~$z));
    }

    private static function k(int $j) {
        if ($j < 16) return 0x00000000;
        if ($j < 32) return 0x5a827999;
        if ($j < 48) return 0x6ed9eba1;
        if ($j < 64) return 0x8f1bbcdc;
        return 0xa953fd4e;
    }
}
