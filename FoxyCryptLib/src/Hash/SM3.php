<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class SM3 {
    private const IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    private const T = [0x79cc4519, 0x7a879d8a];

    private static function rotl($x, $n) { return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff; }
    private static function p0($x) { return $x ^ self::rotl($x, 9) ^ self::rotl($x, 17); }
    private static function p1($x) { return $x ^ self::rotl($x, 15) ^ self::rotl($x, 23); }
    private static function ff($j, $x, $y, $z) { return $j < 16 ? ($x ^ $y ^ $z) : (($x & $y) | ($x & $z) | ($y & $z)); }
    private static function gg($j, $x, $y, $z) { return $j < 16 ? ($x ^ $y ^ $z) : (($x & $y) | ((~$x) & $z)); }

    public static function hash(string $data): string {
        $v = self::IV;
        $len = strlen($data);
        $bitLen = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('N2', 0, $bitLen);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $block = substr($data, $i, 64);
            $w = []; $wp = [];
            for ($j = 0; $j < 16; $j++) {
                $w[$j] = (ord($block[$j*4]) << 24) | (ord($block[$j*4+1]) << 16) | (ord($block[$j*4+2]) << 8) | ord($block[$j*4+3]);
            }
            for ($j = 16; $j < 68; $j++) {
                $w[$j] = self::p1($w[$j-16] ^ $w[$j-9] ^ self::rotl($w[$j-3], 15)) ^ self::rotl($w[$j-13], 7) ^ $w[$j-6];
            }
            for ($j = 0; $j < 64; $j++) {
                $wp[$j] = $w[$j] ^ $w[$j+4];
            }
            $a = $v[0]; $b = $v[1]; $c = $v[2]; $d = $v[3];
            $e = $v[4]; $f = $v[5]; $g = $v[6]; $h = $v[7];
            for ($j = 0; $j < 64; $j++) {
                $ss1 = self::rotl((self::rotl($a, 12) + $e + self::rotl(self::T[intdiv($j, 32)], $j % 32)) & 0xffffffff, 7);
                $ss2 = ($ss1 ^ self::rotl($a, 12)) & 0xffffffff;
                $tt1 = (self::ff($j, $a, $b, $c) + $d + $ss2 + $wp[$j]) & 0xffffffff;
                $tt2 = (self::gg($j, $e, $f, $g) + $h + $ss1 + $w[$j]) & 0xffffffff;
                $d = $c; $c = self::rotl($b, 9); $b = $a; $a = $tt1;
                $h = $g; $g = self::rotl($f, 19); $f = $e; $e = self::p0($tt2);
            }
            $v[0] ^= $a; $v[1] ^= $b; $v[2] ^= $c; $v[3] ^= $d;
            $v[4] ^= $e; $v[5] ^= $f; $v[6] ^= $g; $v[7] ^= $h;
        }
        return pack('N8', $v[0], $v[1], $v[2], $v[3], $v[4], $v[5], $v[6], $v[7]);
    }
}
