<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class Base64 {
    private const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    private const URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    public static function encode(string $data, bool $urlSafe = false): string {
        $alpha = $urlSafe ? self::URL_ALPHABET : self::STD_ALPHABET;
        $result = '';
        $len = strlen($data);
        $i = 0;
        while ($i + 3 <= $len) {
            $b0 = ord($data[$i]);
            $b1 = ord($data[$i + 1]);
            $b2 = ord($data[$i + 2]);
            $result .= $alpha[($b0 >> 2) & 0x3f];
            $result .= $alpha[(($b0 << 4) | ($b1 >> 4)) & 0x3f];
            $result .= $alpha[(($b1 << 2) | ($b2 >> 6)) & 0x3f];
            $result .= $alpha[$b2 & 0x3f];
            $i += 3;
        }
        $rem = $len - $i;
        if ($rem === 2) {
            $b0 = ord($data[$i]);
            $b1 = ord($data[$i + 1]);
            $result .= $alpha[($b0 >> 2) & 0x3f];
            $result .= $alpha[(($b0 << 4) | ($b1 >> 4)) & 0x3f];
            $result .= $alpha[($b1 << 2) & 0x3f];
            $result .= $urlSafe ? '' : '=';
        } elseif ($rem === 1) {
            $b0 = ord($data[$i]);
            $result .= $alpha[($b0 >> 2) & 0x3f];
            $result .= $alpha[($b0 << 4) & 0x3f];
            $result .= $urlSafe ? '' : '==';
        }
        return $result;
    }

    public static function decode(string $data, bool $urlSafe = false): string {
        $data = rtrim($data, "=\x20\t\n\r\0\x0b");
        $alpha = $urlSafe ? self::URL_ALPHABET : self::STD_ALPHABET;
        $map = array_flip(str_split($alpha));
        $result = '';
        $len = strlen($data);
        $i = 0;
        while ($i + 4 <= $len) {
            $c0 = $map[$data[$i]] ?? -1;
            $c1 = $map[$data[$i + 1]] ?? -1;
            $c2 = $map[$data[$i + 2]] ?? -1;
            $c3 = $map[$data[$i + 3]] ?? -1;
            if ($c0 < 0 || $c1 < 0 || $c2 < 0 || $c3 < 0) break;
            $result .= chr((($c0 << 2) | ($c1 >> 4)) & 0xff);
            $result .= chr((($c1 << 4) | ($c2 >> 2)) & 0xff);
            $result .= chr((($c2 << 6) | $c3) & 0xff);
            $i += 4;
        }
        $rem = $len - $i;
        if ($rem >= 2) {
            $c0 = $map[$data[$i]] ?? -1;
            $c1 = $map[$data[$i + 1]] ?? -1;
            if ($c0 < 0 || $c1 < 0) return $result;
            $result .= chr((($c0 << 2) | ($c1 >> 4)) & 0xff);
            if ($rem >= 3) {
                $c2 = $map[$data[$i + 2]] ?? -1;
                if ($c2 < 0) return $result;
                $result .= chr((($c1 << 4) | ($c2 >> 2)) & 0xff);
            }
        }
        return $result;
    }
}
