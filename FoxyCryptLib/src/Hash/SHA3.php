<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class SHA3 {
    private const RC = [
        '0x0000000000000001', '0x0000000000008082', '0x800000000000808a', '0x8000000080008000',
        '0x000000000000808b', '0x0000000080000001', '0x8000000080008081', '0x8000000000008009',
        '0x000000000000008a', '0x0000000000000088', '0x0000000080008009', '0x000000008000000a',
        '0x000000008000808b', '0x800000000000008b', '0x8000000000008089', '0x8000000000008003',
        '0x8000000000008002', '0x8000000000000080', '0x000000000000800a', '0x800000008000000a',
        '0x8000000080008081', '0x8000000000008080', '0x0000000080000001', '0x8000000080008008',
    ];

    private static function keccakF(array &$state): void {
        $rcGMP = [];
        foreach (self::RC as $rc) $rcGMP[] = gmp_init($rc);
        $mask = gmp_init('0xffffffffffffffff');

        for ($round = 0; $round < 24; $round++) {
            // Theta
            $C = [];
            for ($x = 0; $x < 5; $x++) {
                $c = gmp_init(0);
                for ($y = 0; $y < 5; $y++) $c = gmp_xor($c, $state[$x][$y]);
                $C[$x] = $c;
            }
            $D = [];
            for ($x = 0; $x < 5; $x++) {
                $c2 = gmp_xor(gmp_mul($C[($x + 1) % 5], gmp_init(2)), gmp_div_q($C[($x + 1) % 5], gmp_init('0x8000000000000000')));
                $D[$x] = gmp_xor($C[($x + 4) % 5], gmp_and($c2, $mask));
            }
            for ($x = 0; $x < 5; $x++) {
                for ($y = 0; $y < 5; $y++) $state[$x][$y] = gmp_xor($state[$x][$y], $D[$x]);
            }

            // Rho Pi
            $x = 1; $y = 0;
            $current = $state[$x][$y];
            for ($t = 0; $t < 24; $t++) {
                $nx = $y;
                $ny = (2 * $x + 3 * $y) % 5;
                $temp = $state[$nx][$ny];
                $rot = ((($t + 1) * ($t + 2)) >> 1) % 64;
                $state[$nx][$ny] = gmp_and(gmp_or(gmp_mul($current, gmp_pow(gmp_init(2), $rot)), gmp_div_q($current, gmp_pow(gmp_init(2), 64 - $rot))), $mask);
                $current = $temp;
                $x = $nx; $y = $ny;
            }

            // Chi
            for ($y = 0; $y < 5; $y++) {
                $col = [];
                for ($x = 0; $x < 5; $x++) $col[$x] = $state[$x][$y];
                for ($x = 0; $x < 5; $x++) {
                    $not = gmp_and(gmp_com($col[($x + 1) % 5]), $mask);
                    $state[$x][$y] = gmp_xor($col[$x], gmp_and($not, $col[($x + 2) % 5]));
                }
            }

            // Iota
            $state[0][0] = gmp_xor($state[0][0], $rcGMP[$round]);
        }
    }

    private static function sponge(string $data, int $rate, int $outputLen, int $suffix): string {
        $rateBytes = $rate >> 3;
        $mask = gmp_init('0xffffffffffffffff');

        // Initialize state
        $state = [];
        for ($x = 0; $x < 5; $x++) {
            for ($y = 0; $y < 5; $y++) $state[$x][$y] = gmp_init(0);
        }

        // Pad (10*1 padding with suffix)
        $data .= chr($suffix);
        while ((strlen($data) % $rateBytes) !== ($rateBytes - 1)) $data .= "\x00";
        $data .= "\x80";

        // Absorb
        for ($i = 0; $i < strlen($data); $i += $rateBytes) {
            $block = substr($data, $i, $rateBytes);
            for ($j = 0; $j < strlen($block); $j++) {
                $laneId = intdiv($j, 8);
                $byteInLane = $j & 7;
                $x = $laneId % 5;
                $y = intdiv($laneId, 5);
                $val = gmp_mul(gmp_init(ord($block[$j])), gmp_pow(gmp_init(2), $byteInLane * 8));
                $state[$x][$y] = gmp_xor($state[$x][$y], $val);
            }
            self::keccakF($state);
        }

        // Squeeze
        $output = '';
        while (strlen($output) < $outputLen) {
            for ($laneId = 0; $laneId < $rateBytes >> 3 && strlen($output) < $outputLen; $laneId++) {
                $x = $laneId % 5;
                $y = intdiv($laneId, 5);
                $v = $state[$x][$y];
                for ($byteInLane = 0; $byteInLane < 8 && strlen($output) < $outputLen; $byteInLane++) {
                    $byte = gmp_intval(gmp_and(gmp_div_q($v, gmp_pow(gmp_init(2), $byteInLane * 8)), gmp_init(0xff)));
                    $output .= chr($byte);
                }
            }
            if (strlen($output) < $outputLen) self::keccakF($state);
        }

        return substr($output, 0, $outputLen);
    }

    public static function sha3_224(string $data): string { return self::sponge($data, 1152, 28, 0x06); }
    public static function sha3_256(string $data): string { return self::sponge($data, 1088, 32, 0x06); }
    public static function sha3_384(string $data): string { return self::sponge($data, 832, 48, 0x06); }
    public static function sha3_512(string $data): string { return self::sponge($data, 576, 64, 0x06); }
    public static function shake128(string $data, int $outputLen): string { return self::sponge($data, 1344, $outputLen, 0x1f); }
    public static function shake256(string $data, int $outputLen): string { return self::sponge($data, 1088, $outputLen, 0x1f); }
    public static function keccak224(string $data): string { return self::sponge($data, 1152, 28, 0x01); }
    public static function keccak256(string $data): string { return self::sponge($data, 1088, 32, 0x01); }
    public static function keccak384(string $data): string { return self::sponge($data, 832, 48, 0x01); }
    public static function keccak512(string $data): string { return self::sponge($data, 576, 64, 0x01); }
}