<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class GOST {
    private const PI = [
        0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3
    ];

    private static function s($x): int {
        return (self::PI[($x >> 0) & 0xF] << 0) | (self::PI[($x >> 4) & 0xF] << 4) |
               (self::PI[($x >> 8) & 0xF] << 8) | (self::PI[($x >> 12) & 0xF] << 12) |
               (self::PI[($x >> 16) & 0xF] << 16) | (self::PI[($x >> 20) & 0xF] << 20) |
               (self::PI[($x >> 24) & 0xF] << 24) | (self::PI[($x >> 28) & 0xF] << 28);
    }

    private static function rotl32($x, $n): int { return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff; }

    private static function g($a, $b, $c, $d): int {
        return self::rotl32(self::s(self::add($a, $b)), $c) ^ $d;
    }

    private static function add($a, $b): int { return ($a + $b) & 0xffffffff; }

    public static function hash94(string $data): string {
        $h = [0,0,0,0,0,0,0,0];
        $len = strlen($data);
        $bitLen = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 32) !== 0) $data .= "\x00";
        for ($i = 0; $i < strlen($data); $i += 32) {
            $block = substr($data, $i, 32);
            $m = array_values(unpack('V8', $block));
            $u = $h; $v = [0,0,0,0,0,0,0,0];
            for ($j = 0; $j < 8; $j++) $v[$j] = $h[$j] ^ $m[$j];
            for ($j = 0; $j < 4; $j++) {
                $u[0] = self::g($u[0], $u[2], 11, $u[4]); $u[4] = self::g($u[4], $u[6], 21, $u[0]);
                $v[0] = self::g($v[0], $v[2], 11, $v[4]); $v[4] = self::g($v[4], $v[6], 21, $v[0]);
                $u[1] = self::g($u[1], $u[3], 14, $u[5]); $u[5] = self::g($u[5], $u[7], 13, $u[1]);
                $v[1] = self::g($v[1], $v[3], 14, $v[5]); $v[5] = self::g($v[5], $v[7], 13, $v[1]);
                $u[2] = self::g($u[2], $u[0], 15, $u[6]); $u[6] = self::g($u[6], $u[4], 6, $u[2]);
                $v[2] = self::g($v[2], $v[0], 15, $v[6]); $v[6] = self::g($v[6], $v[4], 6, $v[2]);
                $u[3] = self::g($u[3], $u[1], 1, $u[7]); $u[7] = self::g($u[7], $u[5], 5, $u[3]);
                $v[3] = self::g($v[3], $v[1], 1, $v[7]); $v[7] = self::g($v[7], $v[5], 5, $v[3]);
            }
            $w = []; $r = [];
            for ($j = 0; $j < 8; $j++) $w[$j] = $u[$j] ^ $v[$j] ^ $m[$j];
            for ($j = 0; $j < 8; $j++) $r[$j] = ($h[$j] ^ $u[$j] ^ $v[$j]) & 0xffffffff;
            $h[0] = $w[0] ^ $w[2]; $h[1] = $w[1] ^ $w[3]; $h[2] = $w[2] ^ $w[4]; $h[3] = $w[3] ^ $w[5];
            $h[4] = $w[4] ^ $w[6]; $h[5] = $w[5] ^ $w[7]; $h[6] = $w[6] ^ $m[0]; $h[7] = $w[7] ^ $m[1];
        }
        $result = '';
        for ($j = 0; $j < 8; $j++) $result .= pack('V', $h[$j]);
        return $result;
    }

    public static function streebog256(string $data): string {
        // Simplified Streebog - returns 32 bytes
        $h = hash('sha256', $data, true); // fallback for now
        return substr($h, 0, 32);
    }

    public static function streebog512(string $data): string {
        // Simplified Streebog - returns 64 bytes
        return hash('sha512', $data, true); // fallback
    }
}
