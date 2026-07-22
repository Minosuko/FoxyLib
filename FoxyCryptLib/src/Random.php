<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class Random {
    private static bool $seeded = false;

    public static function bytes(int $length): string {
        if ($length <= 0) return '';
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }
        if (PHP_OS_FAMILY === 'Windows') {
            $com = @new \COM('CAPICOM.Utilities.2');
            if ($com) {
                $buffer = $com->GetRandom($length, 0);
                if (strlen($buffer) === $length) return $buffer;
            }
        } else {
            $f = @fopen('/dev/urandom', 'rb');
            if ($f) {
                $buffer = fread($f, $length);
                fclose($f);
                if (strlen($buffer) === $length) return $buffer;
            }
        }
        throw new \RuntimeException('No CSPRNG source available');
    }

    private static function fallbackBytes(int $length): string {
        $buffer = '';
        for ($i = 0; $i < $length; $i++) {
            $buffer .= chr(mt_rand(0, 255));
        }
        return $buffer;
    }

    public static function int(int $min, int $max): int {
        $range = $max - $min;
        if ($range <= 0) return $min;
        $bits = 0;
        $t = $range;
        while ($t > 0) { $bits++; $t >>= 1; }
        $bytes = intdiv($bits + 7, 8);
        $mask = (1 << $bits) - 1;
        do {
            $data = self::bytes($bytes);
            $val = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $val = ($val << 8) | ord($data[$i]);
            }
            $val &= $mask;
        } while ($val > $range);
        return $min + $val;
    }

    public static function float(float $min = 0.0, float $max = 1.0): float {
        $val = 0;
        for ($i = 0; $i < 8; $i++) {
            $val = ($val << 8) | ord(self::bytes(1));
        }
        $val = ($val >> 11) / 9007199254740992;
        return $min + $val * ($max - $min);
    }

    public static function string(int $length, string $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'): string {
        $result = '';
        $clen = strlen($chars);
        for ($i = 0; $i < $length; $i++) {
            $result .= $chars[self::int(0, $clen - 1)];
        }
        return $result;
    }

    public static function shuffle(array &$array): void {
        $len = count($array);
        for ($i = $len - 1; $i > 0; $i--) {
            $j = self::int(0, $i);
            $tmp = $array[$i];
            $array[$i] = $array[$j];
            $array[$j] = $tmp;
        }
    }

    public static function seed(int $seed): void {
        mt_srand($seed);
        self::$seeded = true;
    }

    public static function generateSeed(int $length = 32): string {
        return self::bytes($length);
    }
}
