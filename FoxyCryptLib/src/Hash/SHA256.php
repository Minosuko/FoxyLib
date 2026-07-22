<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class SHA256 {
    private const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];

    private const H224 = [
        0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4
    ];

    private const H256 = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ];

    private static function rr(int $x, int $c): int {
        return (($x >> $c) | ($x << (32 - $c))) & 0xffffffff;
    }

    private static function ch(int $x, int $y, int $z): int { return ($x & $y) ^ ((~$x) & $z); }
    private static function maj(int $x, int $y, int $z): int { return ($x & $y) ^ ($x & $z) ^ ($y & $z); }
    private static function bsig0(int $x): int { return self::rr($x, 2) ^ self::rr($x, 13) ^ self::rr($x, 22); }
    private static function bsig1(int $x): int { return self::rr($x, 6) ^ self::rr($x, 11) ^ self::rr($x, 25); }
    private static function ssig0(int $x): int { return self::rr($x, 7) ^ self::rr($x, 18) ^ ($x >> 3); }
    private static function ssig1(int $x): int { return self::rr($x, 17) ^ self::rr($x, 19) ^ ($x >> 10); }

    private static function process(array &$h, string $chunk): void {
        $w = [];
        for ($i = 0; $i < 16; $i++) {
            $w[$i] = (ord($chunk[$i*4]) << 24) | (ord($chunk[$i*4+1]) << 16) | (ord($chunk[$i*4+2]) << 8) | ord($chunk[$i*4+3]);
        }
        for ($i = 16; $i < 64; $i++) {
            $w[$i] = (self::ssig1($w[$i-2]) + $w[$i-7] + self::ssig0($w[$i-15]) + $w[$i-16]) & 0xffffffff;
        }
        $a = $h[0]; $b = $h[1]; $c = $h[2]; $d = $h[3];
        $e = $h[4]; $f = $h[5]; $g = $h[6]; $h0 = $h[7];
        for ($i = 0; $i < 64; $i++) {
            $t1 = ($h0 + self::bsig1($e) + self::ch($e, $f, $g) + self::K[$i] + $w[$i]) & 0xffffffff;
            $t2 = (self::bsig0($a) + self::maj($a, $b, $c)) & 0xffffffff;
            $h0 = $g; $g = $f; $f = $e; $e = ($d + $t1) & 0xffffffff;
            $d = $c; $c = $b; $b = $a; $a = ($t1 + $t2) & 0xffffffff;
        }
        $h[0] = ($h[0] + $a) & 0xffffffff;
        $h[1] = ($h[1] + $b) & 0xffffffff;
        $h[2] = ($h[2] + $c) & 0xffffffff;
        $h[3] = ($h[3] + $d) & 0xffffffff;
        $h[4] = ($h[4] + $e) & 0xffffffff;
        $h[5] = ($h[5] + $f) & 0xffffffff;
        $h[6] = ($h[6] + $g) & 0xffffffff;
        $h[7] = ($h[7] + $h0) & 0xffffffff;
    }

    public static function hash(string $data, bool $is224 = false): string {
        $h = $is224 ? self::H224 : self::H256;
        $len = strlen($data);
        $bits = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 64) !== 56) $data .= "\x00";
        $data .= pack('N2', 0, $bits);
        for ($i = 0; $i < strlen($data); $i += 64) {
            self::process($h, substr($data, $i, 64));
        }
        $result = '';
        $count = $is224 ? 7 : 8;
        for ($i = 0; $i < $count; $i++) {
            $result .= pack('N', $h[$i]);
        }
        return $result;
    }
}
