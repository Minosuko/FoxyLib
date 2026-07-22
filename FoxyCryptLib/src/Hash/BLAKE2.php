<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class BLAKE2 {
    private const ROUNDS = 12;
    private const IV = [
        '0x6a09e667f3bcc908', '0xbb67ae8584caa73b', '0x3c6ef372fe94f82b', '0xa54ff53a5f1d36f1',
        '0x510e527fade682d1', '0x9b05688c2b3e6c1f', '0x1f83d9abfb41bd6b', '0x5be0cd19137e2179'
    ];

    private const SIGMA = [
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
        [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
        [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
        [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
        [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
        [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
        [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
        [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
        [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
    ];

    private static function rotr64($x, int $r): \GMP {
        $r %= 64;
        if ($r === 0) return $x;
        $mask = gmp_init('0xffffffffffffffff');
        return gmp_and(gmp_or(gmp_div_q($x, gmp_pow(gmp_init(2), $r)), gmp_mul($x, gmp_pow(gmp_init(2), 64 - $r))), $mask);
    }

    private static function add64($a, $b): \GMP {
        return gmp_and(gmp_add($a, $b), gmp_init('0xffffffffffffffff'));
    }

    private static function G(array &$v, int $a, int $b, int $c, int $d, $x, $y): void {
        $mask = gmp_init('0xffffffffffffffff');
        $v[$a] = self::add64(self::add64($v[$a], $v[$b]), $x);
        $v[$d] = self::rotr64(gmp_xor($v[$d], $v[$a]), 32);
        $v[$c] = self::add64($v[$c], $v[$d]);
        $v[$b] = self::rotr64(gmp_xor($v[$b], $v[$c]), 24);
        $v[$a] = self::add64(self::add64($v[$a], $v[$b]), $y);
        $v[$d] = self::rotr64(gmp_xor($v[$d], $v[$a]), 16);
        $v[$c] = self::add64($v[$c], $v[$d]);
        $v[$b] = self::rotr64(gmp_xor($v[$b], $v[$c]), 63);
    }

    private static function compress(array &$h, array &$m, array &$t, bool $f): void {
        $ivGMP = [];
        foreach (self::IV as $iv) $ivGMP[] = gmp_init($iv);

        $v = array_merge($h, $ivGMP);
        $v[12] = gmp_xor($v[12], $t[0]);
        $v[13] = gmp_xor($v[13], $t[1]);
        if ($f) $v[14] = gmp_xor($v[14], gmp_init('0xffffffffffffffff'));

        for ($r = 0; $r < self::ROUNDS; $r++) {
            $s = self::SIGMA[$r];
            self::G($v, 0, 4, 8, 12, $m[$s[0]], $m[$s[1]]);
            self::G($v, 1, 5, 9, 13, $m[$s[2]], $m[$s[3]]);
            self::G($v, 2, 6, 10, 14, $m[$s[4]], $m[$s[5]]);
            self::G($v, 3, 7, 11, 15, $m[$s[6]], $m[$s[7]]);
            self::G($v, 0, 5, 10, 15, $m[$s[8]], $m[$s[9]]);
            self::G($v, 1, 6, 11, 12, $m[$s[10]], $m[$s[11]]);
            self::G($v, 2, 7, 8, 13, $m[$s[12]], $m[$s[13]]);
            self::G($v, 3, 4, 9, 14, $m[$s[14]], $m[$s[15]]);
        }

        for ($i = 0; $i < 8; $i++) $h[$i] = gmp_xor(gmp_xor($h[$i], $v[$i]), $v[$i + 8]);
    }

    public static function hash(string $data, int $size = 32, string $key = ''): string {
        $keyLen = strlen($key);
        if ($keyLen > 64) throw new \InvalidArgumentException('Key too long');
        $blockSize = 128;

        $h = [];
        foreach (self::IV as $iv) $h[] = gmp_init($iv);
        $h[0] = gmp_xor($h[0], gmp_init(0x01010000));
        $h[0] = gmp_xor($h[0], gmp_mul(gmp_init($keyLen), gmp_init(256)));
        $h[0] = gmp_xor($h[0], gmp_init($size));

        if ($keyLen > 0) {
            $block = str_pad($key, $blockSize, "\x00");
            $m = [];
            $tmp = unpack('P16', $block);
            for ($i = 0; $i < 16; $i++) $m[] = gmp_init($tmp[$i + 1]);
            $t = [gmp_init(0), gmp_init(0)];
            self::compress($h, $m, $t, false);
        }

        $fullLen = strlen($data);
        $offset = 0;
        $t = [gmp_init(0), gmp_init(0)];

        while ($offset + $blockSize < $fullLen) {
            $block = substr($data, $offset, $blockSize);
            $m = [];
            $tmp = unpack('P16', $block);
            for ($i = 0; $i < 16; $i++) $m[] = gmp_init($tmp[$i + 1]);
            $t[0] = gmp_init($offset + $blockSize);
            self::compress($h, $m, $t, false);
            $offset += $blockSize;
        }

        $last = substr($data, $offset);
        $last = str_pad($last, $blockSize, "\x00");
        $m = [];
        $tmp = unpack('P16', $last);
        for ($i = 0; $i < 16; $i++) $m[] = gmp_init($tmp[$i + 1]);
        $t[0] = gmp_init($fullLen + ($keyLen > 0 ? $blockSize : 0));
        self::compress($h, $m, $t, true);

        $result = '';
        for ($i = 0; $i < $size; $i++) {
            $lane = intdiv($i, 8);
            $shift = 8 * ($i % 8);
            $byte = gmp_intval(gmp_and(gmp_div_q($h[$lane], gmp_pow(gmp_init(2), $shift)), gmp_init(0xff)));
            $result .= chr($byte);
        }

        return $result;
    }
}