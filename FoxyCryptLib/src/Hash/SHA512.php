<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class SHA512 {
    private const K = [
        [0x428a2f98,0xd728ae22],[0x71374491,0x23ef65cd],[0xb5c0fbcf,0xec4d3b2f],[0xe9b5dba5,0x8189dbbc],
        [0x3956c25b,0xf348b538],[0x59f111f1,0xb605d019],[0x923f82a4,0xaf194f9b],[0xab1c5ed5,0xda6d8118],
        [0xd807aa98,0xa3030242],[0x12835b01,0x45706fbe],[0x243185be,0x4ee4b28c],[0x550c7dc3,0xd5ffb4e2],
        [0x72be5d74,0xf27b896f],[0x80deb1fe,0x3b1696b1],[0x9bdc06a7,0x25c71235],[0xc19bf174,0xcf692694],
        [0xe49b69c1,0x9ef14ad2],[0xefbe4786,0x384f25e3],[0x0fc19dc6,0x8b8cd5b5],[0x240ca1cc,0x77ac9c65],
        [0x2de92c6f,0x592b0275],[0x4a7484aa,0x6ea6e483],[0x5cb0a9dc,0xbd41fbd4],[0x76f988da,0x831153b5],
        [0x983e5152,0xee66dfab],[0xa831c66d,0x2db43210],[0xb00327c8,0x98fb213f],[0xbf597fc7,0xbeef0ee4],
        [0xc6e00bf3,0x3da88fc2],[0xd5a79147,0x930aa725],[0x06ca6351,0xe003826f],[0x14292967,0x0a0e6e70],
        [0x27b70a85,0x46d22ffc],[0x2e1b2138,0x5c26c926],[0x4d2c6dfc,0x5ac42aed],[0x53380d13,0x9d95b3df],
        [0x650a7354,0x8baf63de],[0x766a0abb,0x3c77b2a8],[0x81c2c92e,0x47edaee6],[0x92722c85,0x1482353b],
        [0xa2bfe8a1,0x4cf10364],[0xa81a664b,0xbc423001],[0xc24b8b70,0xd0f89791],[0xc76c51a3,0x0654be30],
        [0xd192e819,0xd6ef5218],[0xd6990624,0x5565a910],[0xf40e3585,0x5771202a],[0x106aa070,0x32bbd1b8],
        [0x19a4c116,0xb8d2d0c8],[0x1e376c08,0x5141ab53],[0x2748774c,0xdf8eeb99],[0x34b0bcb5,0xe19b48a8],
        [0x391c0cb3,0xc5c95a63],[0x4ed8aa4a,0xe3418acb],[0x5b9cca4f,0x7763e373],[0x682e6ff3,0xd6b2b8a3],
        [0x748f82ee,0x5defb2fc],[0x78a5636f,0x43172f60],[0x84c87814,0xa1f0ab72],[0x8cc70208,0x1a6439ec],
        [0x90befffa,0x23631e28],[0xa4506ceb,0xde82bde9],[0xbef9a3f7,0xb2c67915],[0xc67178f2,0xe372532b],
        [0xca273ece,0xea26619c],[0xd186b8c7,0x21c0c207],[0xeada7dd6,0xcde0eb1e],[0xf57d4f7f,0xee6ed178],
        [0x06f067aa,0x72176fba],[0x0a637dc5,0xa2c898a6],[0x113f9804,0xbef90dae],[0x1b710b35,0x131c471b],
        [0x28db77f5,0x23047d84],[0x32caab7b,0x40c72493],[0x3c9ebe0a,0x15c9bebc],[0x431d67c4,0x9c100d4c],
        [0x4cc5d4be,0xcb3e42b6],[0x597f299c,0xfc657e2a],[0x5fcb6fab,0x3ad6faec],[0x6c44198c,0x4a475817]
    ];

    // Split each 64-bit IV into hi/lo 32-bit parts
    private static function toU64(array $v): array { return [$v[0] & 0xffffffff, $v[1] & 0xffffffff]; }
    private static function add64(array $a, array $b): array {
        $lo = ($a[1] & 0xffffffff) + ($b[1] & 0xffffffff);
        $hi = ($a[0] & 0xffffffff) + ($b[0] & 0xffffffff) + (int)($lo >> 32);
        return [$hi & 0xffffffff, $lo & 0xffffffff];
    }
    private static function not64(array $x): array { return [~$x[0] & 0xffffffff, ~$x[1] & 0xffffffff]; }
    private static function xor64(array $a, array $b): array { return [$a[0] ^ $b[0], $a[1] ^ $b[1]]; }
    private static function and64(array $a, array $b): array { return [$a[0] & $b[0], $a[1] & $b[1]]; }
    private static function or64(array $a, array $b): array { return [$a[0] | $b[0], $a[1] | $b[1]]; }
    private static function shr64(array $x, int $n): array { return $n >= 32 ? [0, $x[0] >> ($n - 32)] : [$x[0] >> $n, (($x[0] << (32 - $n)) | ($x[1] >> $n)) & 0xffffffff]; }
    private static function shl64(array $x, int $n): array { return $n >= 32 ? [($x[1] << ($n - 32)) & 0xffffffff, 0] : [(($x[0] << $n) | ($x[1] >> (32 - $n))) & 0xffffffff, ($x[1] << $n) & 0xffffffff]; }
    private static function rotr64(array $x, int $n): array {
        $n %= 64;
        if ($n === 0) return $x;
        return self::or64(self::shr64($x, $n), self::shl64($x, 64 - $n));
    }

    private static function ch64(array $x, array $y, array $z): array { return self::xor64(self::and64($x, $y), self::and64(self::not64($x), $z)); }
    private static function maj64(array $x, array $y, array $z): array { return self::xor64(self::xor64(self::and64($x, $y), self::and64($x, $z)), self::and64($y, $z)); }
    private static function bsig0(array $x): array { return self::xor64(self::xor64(self::rotr64($x, 28), self::rotr64($x, 34)), self::rotr64($x, 39)); }
    private static function bsig1(array $x): array { return self::xor64(self::xor64(self::rotr64($x, 14), self::rotr64($x, 18)), self::rotr64($x, 41)); }
    private static function ssig0(array $x): array { return self::xor64(self::xor64(self::rotr64($x, 1), self::rotr64($x, 8)), self::shr64($x, 7)); }
    private static function ssig1(array $x): array { return self::xor64(self::xor64(self::rotr64($x, 19), self::rotr64($x, 61)), self::shr64($x, 6)); }

    private static function fromBytes(string $bytes): array {
        return [(ord($bytes[0]) << 24) | (ord($bytes[1]) << 16) | (ord($bytes[2]) << 8) | ord($bytes[3]),
                (ord($bytes[4]) << 24) | (ord($bytes[5]) << 16) | (ord($bytes[6]) << 8) | ord($bytes[7])];
    }

    private static function toBytes(array $v): string {
        return pack('N', $v[0]) . pack('N', $v[1]);
    }

    private static function process(array &$h, string $chunk): void {
        $w = [];
        for ($i = 0; $i < 16; $i++) {
            $w[$i] = self::fromBytes(substr($chunk, $i * 8, 8));
        }
        for ($i = 16; $i < 80; $i++) {
            $s0 = self::ssig0($w[$i - 15]);
            $s1 = self::ssig1($w[$i - 2]);
            $w[$i] = self::add64(self::add64(self::add64($w[$i - 16], $s0), $w[$i - 7]), $s1);
        }
        list($a, $b, $c, $d, $e, $f, $g, $h0) = [$h[0], $h[1], $h[2], $h[3], $h[4], $h[5], $h[6], $h[7]];
        for ($i = 0; $i < 80; $i++) {
            $t1 = self::add64(self::add64(self::add64(self::add64($h0, self::bsig1($e)), self::ch64($e, $f, $g)), self::K[$i]), $w[$i]);
            $t2 = self::add64(self::bsig0($a), self::maj64($a, $b, $c));
            $h0 = $g; $g = $f; $f = $e;
            $e = self::add64($d, $t1);
            $d = $c; $c = $b; $b = $a;
            $a = self::add64($t1, $t2);
        }
        $h[0] = self::add64($h[0], $a);
        $h[1] = self::add64($h[1], $b);
        $h[2] = self::add64($h[2], $c);
        $h[3] = self::add64($h[3], $d);
        $h[4] = self::add64($h[4], $e);
        $h[5] = self::add64($h[5], $f);
        $h[6] = self::add64($h[6], $g);
        $h[7] = self::add64($h[7], $h0);
    }

    private static function finalize(array $h, int $count): string {
        $result = '';
        for ($i = 0; $i < $count; $i++) {
            $result .= self::toBytes($h[$i]);
        }
        return $result;
    }

    private static function hIV(array $iv): array {
        $result = [];
        for ($i = 0; $i < 8; $i++) {
            $result[$i] = [$iv[$i * 2] & 0xffffffff, $iv[$i * 2 + 1] & 0xffffffff];
        }
        return $result;
    }

    public static function hash512(string $data): string {
        $iv = self::hIV([0x6a09e667,0xf3bcc908,0xbb67ae85,0x84caa73b,0x3c6ef372,0xfe94f82b,0xa54ff53a,0x5f1d36f1,0x510e527f,0xade682d1,0x9b05688c,0x2b3e6c1f,0x1f83d9ab,0xfb41bd6b,0x5be0cd19,0x137e2179]);
        return self::hashVariant($data, $iv, 8);
    }

    public static function hash384(string $data): string {
        $iv = self::hIV([0xcbbb9d5d,0xc1059ed8,0x629a292a,0x367cd507,0x9159015a,0x3070dd17,0x152fecd8,0xf70e5939,0x67332667,0xffc00b31,0x8eb44a87,0x68581511,0xdb0c2e0d,0x64f98fa7,0x47b5481d,0xbefa4fa4]);
        return self::hashVariant($data, $iv, 6);
    }

    public static function hash512_224(string $data): string {
        $iv = self::hIV([0x8c3d37c8,0x19544da2,0x73e19966,0x89dcd4d6,0x1dfab7ae,0x32ff9c82,0x679dd514,0x582f9fcf,0x0f6d2b69,0x7bd44da8,0x77e36f73,0x04c48942,0x3f9d85a8,0x6a1d36c8,0x1112e6ad,0x91d692a1]);
        return self::hashVariant($data, $iv, 3);
    }

    public static function hash512_256(string $data): string {
        $iv = self::hIV([0x22312194,0xfc2bf72c,0x9f555fa3,0xc84c64c2,0x2393b86b,0x6f53b151,0x96387719,0x5940eabd,0x96283ee2,0xa88effe3,0xbe5e1e25,0x53863992,0x2b0199fc,0x2c85b8aa,0x0eb72ddc,0x81c52ca2]);
        return self::hashVariant($data, $iv, 4);
    }

    private static function hashVariant(string $data, array $h, int $outWords): string {
        $len = strlen($data);
        $bits = $len * 8;
        $data .= "\x80";
        while ((strlen($data) % 128) !== 112) $data .= "\x00";
        $data .= pack('N2', 0, 0) . pack('N2', 0, $bits);
        for ($i = 0; $i < strlen($data); $i += 128) {
            self::process($h, substr($data, $i, 128));
        }
        return self::finalize($h, $outWords);
    }
}
