<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class Base32 {
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const HEX_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

    public static function encode(string $data, bool $hex = false): string {
        $alpha = $hex ? self::HEX_ALPHABET : self::ALPHABET;
        $result = '';
        $len = strlen($data);
        $i = 0;
        while ($i + 5 <= $len) {
            $b0 = ord($data[$i]);
            $b1 = ord($data[$i + 1]);
            $b2 = ord($data[$i + 2]);
            $b3 = ord($data[$i + 3]);
            $b4 = ord($data[$i + 4]);
            $result .= $alpha[($b0 >> 3) & 0x1f];
            $result .= $alpha[(($b0 << 2) | ($b1 >> 6)) & 0x1f];
            $result .= $alpha[($b1 >> 1) & 0x1f];
            $result .= $alpha[(($b1 << 4) | ($b2 >> 4)) & 0x1f];
            $result .= $alpha[(($b2 << 1) | ($b3 >> 7)) & 0x1f];
            $result .= $alpha[($b3 >> 2) & 0x1f];
            $result .= $alpha[(($b3 << 3) | ($b4 >> 5)) & 0x1f];
            $result .= $alpha[$b4 & 0x1f];
            $i += 5;
        }
        $rem = $len - $i;
        if ($rem === 4) {
            $b0 = ord($data[$i]); $b1 = ord($data[$i + 1]); $b2 = ord($data[$i + 2]); $b3 = ord($data[$i + 3]);
            $result .= $alpha[($b0 >> 3) & 0x1f] . $alpha[(($b0 << 2) | ($b1 >> 6)) & 0x1f];
            $result .= $alpha[($b1 >> 1) & 0x1f] . $alpha[(($b1 << 4) | ($b2 >> 4)) & 0x1f];
            $result .= $alpha[(($b2 << 1) | ($b3 >> 7)) & 0x1f] . $alpha[($b3 >> 2) & 0x1f];
            $result .= $alpha[($b3 << 3) & 0x1f] . '=====';
        } elseif ($rem === 3) {
            $b0 = ord($data[$i]); $b1 = ord($data[$i + 1]); $b2 = ord($data[$i + 2]);
            $result .= $alpha[($b0 >> 3) & 0x1f] . $alpha[(($b0 << 2) | ($b1 >> 6)) & 0x1f];
            $result .= $alpha[($b1 >> 1) & 0x1f] . $alpha[(($b1 << 4) | ($b2 >> 4)) & 0x1f];
            $result .= $alpha[($b2 << 1) & 0x1f] . '=====';
        } elseif ($rem === 2) {
            $b0 = ord($data[$i]); $b1 = ord($data[$i + 1]);
            $result .= $alpha[($b0 >> 3) & 0x1f] . $alpha[(($b0 << 2) | ($b1 >> 6)) & 0x1f];
            $result .= $alpha[($b1 >> 1) & 0x1f] . $alpha[(($b1 << 4)) & 0x1f] . '=====';
        } elseif ($rem === 1) {
            $b0 = ord($data[$i]);
            $result .= $alpha[($b0 >> 3) & 0x1f] . $alpha[($b0 << 2) & 0x1f] . '======';
        }
        return $result;
    }

    public static function decode(string $data, bool $hex = false): string {
        $data = strtoupper(rtrim($data, "=\x20\t\n\r\0\x0b"));
        $alpha = $hex ? self::HEX_ALPHABET : self::ALPHABET;
        $map = array_flip(str_split($alpha));
        $result = '';
        $len = strlen($data);
        $i = 0;
        while ($i + 8 <= $len) {
            $c0 = $map[$data[$i]] ?? -1; $c1 = $map[$data[$i + 1]] ?? -1;
            $c2 = $map[$data[$i + 2]] ?? -1; $c3 = $map[$data[$i + 3]] ?? -1;
            $c4 = $map[$data[$i + 4]] ?? -1; $c5 = $map[$data[$i + 5]] ?? -1;
            $c6 = $map[$data[$i + 6]] ?? -1; $c7 = $map[$data[$i + 7]] ?? -1;
            if ($c0 < 0 || $c1 < 0 || $c2 < 0 || $c3 < 0 || $c4 < 0 || $c5 < 0 || $c6 < 0 || $c7 < 0) break;
            $result .= chr((($c0 << 3) | ($c1 >> 2)) & 0xff);
            $result .= chr((($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff);
            $result .= chr((($c3 << 4) | ($c4 >> 1)) & 0xff);
            $result .= chr((($c4 << 7) | ($c5 << 2) | ($c6 >> 3)) & 0xff);
            $result .= chr((($c6 << 5) | $c7) & 0xff);
            $i += 8;
        }
        $rem = $len - $i;
        if ($rem >= 2) {
            $c = [];
            for ($j = 0; $j < $rem; $j++) {
                $c[$j] = $map[$data[$i + $j]] ?? -1;
                if ($c[$j] < 0) return $result;
            }
            if ($rem >= 2) {
                $result .= chr((($c[0] << 3) | ($c[1] >> 2)) & 0xff);
            }
            if ($rem >= 4) {
                $result .= chr((($c[1] << 6) | ($c[2] << 1) | ($c[3] >> 4)) & 0xff);
            }
            if ($rem >= 5) {
                $result .= chr((($c[3] << 4) | ($c[4] >> 1)) & 0xff);
            }
            if ($rem >= 7) {
                $result .= chr((($c[4] << 7) | ($c[5] << 2) | ($c[6] >> 3)) & 0xff);
            }
        }
        return $result;
    }
}
