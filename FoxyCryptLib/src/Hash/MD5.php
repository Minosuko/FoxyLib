<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class MD5 {
    private const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    private const T = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391];

    public static function hash(string $data): string {
        $a = 0x67452301; $b = 0xefcdab89; $c = 0x98badcfe; $d = 0x10325476;
        $len = strlen($data);
        $bitLen = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('V', $bitLen) . str_repeat("\x00", 4);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $block = substr($data, $i, 64);
            $x = array_values(unpack('V16', $block));
            $aa = $a; $bb = $b; $cc = $c; $dd = $d;
            for ($j = 0; $j < 64; $j++) {
                $g = $j < 16 ? $j : ($j < 32 ? (5 * $j + 1) % 16 : ($j < 48 ? (3 * $j + 5) % 16 : (7 * $j) % 16));
                $f = $j < 16 ? (($bb & $cc) | ((~$bb) & $dd)) : ($j < 32 ? (($dd & $bb) | ((~$dd) & $cc)) : ($j < 48 ? ($bb ^ $cc ^ $dd) : ($cc ^ ($bb | (~$dd)))));
                $temp = $dd;
                $dd = $cc;
                $cc = $bb;
                $bb = self::add($bb, self::rotl(self::add(self::add($aa, $f), self::add(self::T[$j], $x[$g])), self::S[$j]));
                $aa = $temp;
            }
            $a = self::add($a, $aa); $b = self::add($b, $bb); $c = self::add($c, $cc); $d = self::add($d, $dd);
        }
        return pack('V4', $a, $b, $c, $d);
    }

    private static function rotl(int $x, int $n): int { return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff; }
    private static function add(int $a, int $b): int { return ($a + $b) & 0xffffffff; }

    public static function md2(string $data): string {
        $pi = [41,46,67,201,162,216,124,1,61,54,84,161,236,240,6,19,98,167,5,243,192,199,115,140,152,147,43,217,188,76,130,202,30,155,87,60,253,212,224,22,103,66,111,24,138,23,229,18,190,78,196,214,218,158,222,73,160,251,245,142,187,47,238,122,169,104,121,145,21,178,7,63,148,194,16,137,11,34,95,33,128,127,93,154,90,144,50,39,53,62,204,231,191,247,151,3,255,25,48,179,72,165,181,209,215,94,146,42,172,86,170,198,79,184,56,210,150,164,125,182,118,252,107,226,156,116,4,241,69,157,112,89,100,113,135,32,134,91,207,101,230,45,168,2,27,96,37,173,174,176,185,246,28,70,97,105,52,64,126,15,85,71,163,35,221,81,175,58,195,92,249,206,186,197,234,38,44,83,13,110,133,40,132,9,211,223,205,244,65,129,77,82,106,220,55,200,108,193,171,250,36,225,123,8,12,189,177,74,120,136,149,139,227,99,232,109,233,203,213,254,59,0,29,57,242,239,183,14,102,88,208,228,166,119,114,248,235,117,75,10,49,68,80,180,143,237,31,26,219,153,141,51,159,17,131,20];
        $state = str_repeat("\x00", 48);
        $len = strlen($data);
        $checksum = str_repeat("\x00", 16);
        $padding = 16 - ($len % 16);
        $data .= str_repeat(chr($padding), $padding);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            for ($j = 0; $j < 16; $j++) {
                $state[16+$j] = $block[$j];
                $state[32+$j] = chr(ord($state[16+$j]) ^ ord($state[$j]));
            }
            $t = 0;
            for ($j = 0; $j < 18; $j++) {
                for ($k = 0; $k < 48; $k++) {
                    $t = ord($state[$k]) ^ $pi[$t];
                    $state[$k] = chr($t);
                }
                $t = ($t + $j) % 256;
            }
            for ($j = 0; $j < 16; $j++) {
                $checksum[$j] = chr(ord($checksum[$j]) ^ $pi[ord($block[$j]) ^ ord($checksum[$j])]);
            }
        }
        for ($i = 0; $i < 16; $i += 16) {
            $block = substr($checksum, $i, 16);
            for ($j = 0; $j < 16; $j++) {
                $state[16+$j] = $block[$j];
                $state[32+$j] = chr(ord($state[16+$j]) ^ ord($state[$j]));
            }
            $t = 0;
            for ($j = 0; $j < 18; $j++) {
                for ($k = 0; $k < 48; $k++) {
                    $t = ord($state[$k]) ^ $pi[$t];
                    $state[$k] = chr($t);
                }
                $t = ($t + $j) % 256;
            }
        }
        return substr($state, 0, 16);
    }

    public static function md4(string $data): string {
        $a = 0x67452301; $b = 0xefcdab89; $c = 0x98badcfe; $d = 0x10325476;
        $len = strlen($data);
        $bitLen = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('V', $bitLen) . str_repeat("\x00", 4);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $block = substr($data, $i, 64);
            $x = array_values(unpack('V16', $block));
            $aa = $a; $bb = $b; $cc = $c; $dd = $d;
            $round = function($a, $b, $c, $d, $k, $s, $type) {
                $f = $type === 0 ? (($b & $c) | ((~$b) & $d)) : ($type === 1 ? (($b & $c) | ($b & $d) | ($c & $d)) : ($b ^ $c ^ $d));
                return self::rotl(self::add($a, $f, $x[$k]), $s);
            };
            for ($j = 0; $j < 16; $j++) {
                $temp = $d; $d = $c; $c = $b;
                $b = self::rotl(self::add(self::add($a, ($j < 4 ? (($b & $c) | ((~$b) & $d)) : ($j < 8 ? (($b & $c) | ($b & $d) | ($c & $d)) : ($b ^ $c ^ $d)))), $x[$j % 16]), [3,7,11,19][$j % 4]);
                $a = $temp;
            }
            // Simplified: use proper MD4 rounds
            // Round 1
            $a = self::ff($a, $b, $c, $d, $x[0], 3); $d = self::ff($d, $a, $b, $c, $x[1], 7); $c = self::ff($c, $d, $a, $b, $x[2], 11); $b = self::ff($b, $c, $d, $a, $x[3], 19);
            $a = self::ff($a, $b, $c, $d, $x[4], 3); $d = self::ff($d, $a, $b, $c, $x[5], 7); $c = self::ff($c, $d, $a, $b, $x[6], 11); $b = self::ff($b, $c, $d, $a, $x[7], 19);
            $a = self::ff($a, $b, $c, $d, $x[8], 3); $d = self::ff($d, $a, $b, $c, $x[9], 7); $c = self::ff($c, $d, $a, $b, $x[10], 11); $b = self::ff($b, $c, $d, $a, $x[11], 19);
            $a = self::ff($a, $b, $c, $d, $x[12], 3); $d = self::ff($d, $a, $b, $c, $x[13], 7); $c = self::ff($c, $d, $a, $b, $x[14], 11); $b = self::ff($b, $c, $d, $a, $x[15], 19);
            // Round 2
            $a = self::gg($a, $b, $c, $d, $x[0], 3); $d = self::gg($d, $a, $b, $c, $x[4], 5); $c = self::gg($c, $d, $a, $b, $x[8], 9); $b = self::gg($b, $c, $d, $a, $x[12], 13);
            $a = self::gg($a, $b, $c, $d, $x[1], 3); $d = self::gg($d, $a, $b, $c, $x[5], 5); $c = self::gg($c, $d, $a, $b, $x[9], 9); $b = self::gg($b, $c, $d, $a, $x[13], 13);
            $a = self::gg($a, $b, $c, $d, $x[2], 3); $d = self::gg($d, $a, $b, $c, $x[6], 5); $c = self::gg($c, $d, $a, $b, $x[10], 9); $b = self::gg($b, $c, $d, $a, $x[14], 13);
            $a = self::gg($a, $b, $c, $d, $x[3], 3); $d = self::gg($d, $a, $b, $c, $x[7], 5); $c = self::gg($c, $d, $a, $b, $x[11], 9); $b = self::gg($b, $c, $d, $a, $x[15], 13);
            // Round 3
            $a = self::hh($a, $b, $c, $d, $x[0], 3); $d = self::hh($d, $a, $b, $c, $x[8], 9); $c = self::hh($c, $d, $a, $b, $x[4], 11); $b = self::hh($b, $c, $d, $a, $x[12], 15);
            $a = self::hh($a, $b, $c, $d, $x[2], 3); $d = self::hh($d, $a, $b, $c, $x[10], 9); $c = self::hh($c, $d, $a, $b, $x[6], 11); $b = self::hh($b, $c, $d, $a, $x[14], 15);
            $a = self::hh($a, $b, $c, $d, $x[1], 3); $d = self::hh($d, $a, $b, $c, $x[9], 9); $c = self::hh($c, $d, $a, $b, $x[5], 11); $b = self::hh($b, $c, $d, $a, $x[13], 15);
            $a = self::hh($a, $b, $c, $d, $x[3], 3); $d = self::hh($d, $a, $b, $c, $x[11], 9); $c = self::hh($c, $d, $a, $b, $x[7], 11); $b = self::hh($b, $c, $d, $a, $x[15], 15);
            $a = self::add($a, $aa); $b = self::add($b, $bb); $c = self::add($c, $cc); $d = self::add($d, $dd);
        }
        return pack('V4', $a, $b, $c, $d);
    }

    private static function ff($a, $b, $c, $d, $x, $s) { return self::rotl(self::add($a, (($b & $c) | ((~$b) & $d)), $x), $s); }
    private static function gg($a, $b, $c, $d, $x, $s) { return self::rotl(self::add($a, (($b & $c) | ($b & $d) | ($c & $d)), $x, 0x5a827999), $s); }
    private static function hh($a, $b, $c, $d, $x, $s) { return self::rotl(self::add($a, ($b ^ $c ^ $d), $x, 0x6ed9eba1), $s); }
}

// MD4 is in same file, MD6 is not included as it was never standardized
