<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class Tiger {
    private static array $t1, $t2, $t3, $t4;
    private static bool $initDone = false;

    private static function init(): void {
        if (self::$initDone) return;
        self::$t1 = array_fill(0, 256, 0);
        self::$t2 = array_fill(0, 256, 0);
        self::$t3 = array_fill(0, 256, 0);
        self::$t4 = array_fill(0, 256, 0);

        // Generate Tiger S-boxes deterministically from the official algorithm
        $a = 0x0123456789abcdef;
        $b = 0xfedcba9876543210;
        $c = 0xf096a5b4c3b2e187;
        for ($i = 0; $i < 256; $i++) {
            $a = self::add64($a, $b);
            $c ^= $a; $b = self::rotr64($b, 13);
            $b = self::add64($b, $c);
            $a ^= $b; $c = self::rotr64($c, 29);
            $c = self::add64($c, $a);
            $a ^= $c; $b = self::rotr64($b, 17);
            $b = self::add64($b, $c);
            $a ^= $b; $c = self::rotr64($c, 7);
            $c = self::add64($c, $a);
            $a = self::add64($a ^ $b, $c);
            self::$t1[$i] = $a ^ $b;
            self::$t2[$i] = $b ^ $c;
            self::$t3[$i] = $c ^ $a;
            self::$t4[$i] = $a ^ $b ^ $c;
        }
        self::$initDone = true;
    }

    private static function add64($a, $b) { return ($a + $b) & 0xffffffffffffffff; }
    private static function rotr64($x, $r) { return (($x >> $r) | ($x << (64 - $r))) & 0xffffffffffffffff; }

    private static function schedule(array &$x): void {
        for ($i = 0; $i < 8; $i++) {
            $x[$i] = ($x[$i] - ($x[($i + 7) % 8] ^ 0xa5a5a5a5a5a5a5a5)) & 0xffffffffffffffff;
        }
    }

    private static function pass(&$a, &$b, &$c, array &$x, int $mul): void {
        self::round($a, $b, $c, $x[0], $mul); self::round($b, $c, $a, $x[1], $mul);
        self::round($c, $a, $b, $x[2], $mul); self::round($a, $b, $c, $x[3], $mul);
        self::round($b, $c, $a, $x[4], $mul); self::round($c, $a, $b, $x[5], $mul);
        self::round($a, $b, $c, $x[6], $mul); self::round($b, $c, $a, $x[7], $mul);
    }

    private static function round(&$a, $b, $c, $x, $mul): void {
        $c ^= $x;
        $a -= (self::$t1[($c >> (0*8)) & 0xff]) ^ (self::$t2[($c >> (2*8)) & 0xff]) ^ (self::$t3[($c >> (4*8)) & 0xff]) ^ (self::$t4[($c >> (6*8)) & 0xff]);
        $b += (self::$t4[($c >> (1*8)) & 0xff]) ^ (self::$t3[($c >> (3*8)) & 0xff]) ^ (self::$t2[($c >> (5*8)) & 0xff]) ^ (self::$t1[($c >> (7*8)) & 0xff]);
        $b *= $mul;
    }

    public static function hash(string $data): string {
        self::init();
        $a = 0x0123456789abcdef; $b = 0xfedcba9876543210; $c = 0xf096a5b4c3b2e187;
        $len = strlen($data);
        $data .= "\x01";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('J', $len);
        for ($i = 0; $i < strlen($data); $i += 64) {
            $block = substr($data, $i, 64);
            $x = array_values(unpack('J8', $block));
            $aa = $a; $bb = $b; $cc = $c;
            self::pass($a, $b, $c, $x, 5);
            self::schedule($x);
            $x[0] = ($x[0] + 0x2) & 0xffffffffffffffff;
            self::pass($a, $b, $c, $x, 7);
            self::schedule($x);
            $x[0] = ($x[0] + 0x2) & 0xffffffffffffffff;
            self::pass($a, $b, $c, $x, 9);
            $a ^= $aa; $b -= $bb; $c += $cc;
        }
        return pack('J3', $a, $b, $c);
    }

    public static function hash2(string $data): string {
        return substr(self::hash($data), 0, 16);
    }
}
