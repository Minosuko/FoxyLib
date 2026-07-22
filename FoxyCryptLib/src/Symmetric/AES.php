<?php
declare(strict_types=1);
namespace FoxyCryptLib\Symmetric;

class AES {
    private const SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    ];

    private const RSBOX = [
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    ];

    private const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

    private const GF_MUL = [
        [], [], [], [],
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        [], [], [], [],
        [], [], [], []
    ];

    private static function xtime(int $a): int {
        return (($a << 1) ^ (($a >> 7) * 0x1b)) & 0xff;
    }

    private static function gfMul(int $a, int $b): int {
        $result = 0;
        for ($i = 0; $i < 8; $i++) {
            if ($b & 1) $result ^= $a;
            $a = self::xtime($a);
            $b >>= 1;
        }
        return $result;
    }

    private array $roundKeys;
    private int $nRounds;
    private int $keyLen;

    public function __construct(string $key) {
        $this->keyLen = strlen($key);
        $this->nRounds = match($this->keyLen) {
            16 => 10,
            24 => 12,
            32 => 14,
            default => throw new \InvalidArgumentException('Invalid key length: ' . $this->keyLen)
        };
        $this->roundKeys = $this->keyExpansion($key);
    }

    private function keyExpansion(string $key): array {
        $nK = $this->keyLen / 4;
        $nR = $this->nRounds;
        $w = [];
        for ($i = 0; $i < $nK; $i++) {
            $w[$i] = array_values(unpack('N', substr($key, $i * 4, 4)))[0];
        }
        for ($i = $nK; $i < 4 * ($nR + 1); $i++) {
            $temp = $w[$i - 1];
            if ($i % $nK === 0) {
                $temp = self::rotWord($temp);
                $temp = self::subWord($temp);
                $temp ^= (self::RCON[intdiv($i, $nK) - 1] << 24);
            } elseif ($nK > 6 && $i % $nK === 4) {
                $temp = self::subWord($temp);
            }
            $w[$i] = $w[$i - $nK] ^ $temp;
        }
        return $w;
    }

    private static function rotWord(int $w): int {
        return (($w << 8) | ($w >> 24)) & 0xffffffff;
    }

    private static function subWord(int $w): int {
        return (self::SBOX[($w >> 24) & 0xff] << 24) |
               (self::SBOX[($w >> 16) & 0xff] << 16) |
               (self::SBOX[($w >> 8) & 0xff] << 8) |
               self::SBOX[$w & 0xff];
    }

    private static function subBytes(string $block): string {
        $result = '';
        for ($i = 0; $i < 16; $i++) {
            $result .= chr(self::SBOX[ord($block[$i])]);
        }
        return $result;
    }

    private static function invSubBytes(string $block): string {
        $result = '';
        for ($i = 0; $i < 16; $i++) {
            $result .= chr(self::RSBOX[ord($block[$i])]);
        }
        return $result;
    }

    private static function shiftRows(string $block): string {
        return $block[0] . $block[5] . $block[10] . $block[15] .
               $block[4] . $block[9] . $block[14] . $block[3] .
               $block[8] . $block[13] . $block[2] . $block[7] .
               $block[12] . $block[1] . $block[6] . $block[11];
    }

    private static function invShiftRows(string $block): string {
        return $block[0] . $block[13] . $block[10] . $block[7] .
               $block[4] . $block[1] . $block[14] . $block[11] .
               $block[8] . $block[5] . $block[2] . $block[15] .
               $block[12] . $block[9] . $block[6] . $block[3];
    }

    private static function mixColumns(string $block): string {
        $result = '';
        for ($c = 0; $c < 4; $c++) {
            $i = $c * 4;
            $a = [ord($block[$i]), ord($block[$i+1]), ord($block[$i+2]), ord($block[$i+3])];
            $result .= chr(self::gfMul(2, $a[0]) ^ self::gfMul(3, $a[1]) ^ $a[2] ^ $a[3]);
            $result .= chr($a[0] ^ self::gfMul(2, $a[1]) ^ self::gfMul(3, $a[2]) ^ $a[3]);
            $result .= chr($a[0] ^ $a[1] ^ self::gfMul(2, $a[2]) ^ self::gfMul(3, $a[3]));
            $result .= chr(self::gfMul(3, $a[0]) ^ $a[1] ^ $a[2] ^ self::gfMul(2, $a[3]));
        }
        return $result;
    }

    private static function invMixColumns(string $block): string {
        $result = '';
        for ($c = 0; $c < 4; $c++) {
            $i = $c * 4;
            $a = [ord($block[$i]), ord($block[$i+1]), ord($block[$i+2]), ord($block[$i+3])];
            $result .= chr(self::gfMul(14, $a[0]) ^ self::gfMul(11, $a[1]) ^ self::gfMul(13, $a[2]) ^ self::gfMul(9, $a[3]));
            $result .= chr(self::gfMul(9, $a[0]) ^ self::gfMul(14, $a[1]) ^ self::gfMul(11, $a[2]) ^ self::gfMul(13, $a[3]));
            $result .= chr(self::gfMul(13, $a[0]) ^ self::gfMul(9, $a[1]) ^ self::gfMul(14, $a[2]) ^ self::gfMul(11, $a[3]));
            $result .= chr(self::gfMul(11, $a[0]) ^ self::gfMul(13, $a[1]) ^ self::gfMul(9, $a[2]) ^ self::gfMul(14, $a[3]));
        }
        return $result;
    }

    private function addRoundKey(string $block, int $round): string {
        $result = '';
        for ($i = 0; $i < 4; $i++) {
            $rk = $this->roundKeys[$round * 4 + $i];
            $result .= chr(ord($block[$i*4]) ^ (($rk >> 24) & 0xff));
            $result .= chr(ord($block[$i*4+1]) ^ (($rk >> 16) & 0xff));
            $result .= chr(ord($block[$i*4+2]) ^ (($rk >> 8) & 0xff));
            $result .= chr(ord($block[$i*4+3]) ^ ($rk & 0xff));
        }
        return $result;
    }

    public function encryptBlock(string $block): string {
        if (strlen($block) !== 16) throw new \InvalidArgumentException('Block must be 16 bytes');
        $state = $this->addRoundKey($block, 0);
        for ($r = 1; $r < $this->nRounds; $r++) {
            $state = self::subBytes($state);
            $state = self::shiftRows($state);
            $state = self::mixColumns($state);
            $state = $this->addRoundKey($state, $r);
        }
        $state = self::subBytes($state);
        $state = self::shiftRows($state);
        $state = $this->addRoundKey($state, $this->nRounds);
        return $state;
    }

    public function decryptBlock(string $block): string {
        if (strlen($block) !== 16) throw new \InvalidArgumentException('Block must be 16 bytes');
        $state = $this->addRoundKey($block, $this->nRounds);
        for ($r = $this->nRounds - 1; $r >= 1; $r--) {
            $state = self::invShiftRows($state);
            $state = self::invSubBytes($state);
            $state = $this->addRoundKey($state, $r);
            $state = self::invMixColumns($state);
        }
        $state = self::invShiftRows($state);
        $state = self::invSubBytes($state);
        $state = $this->addRoundKey($state, 0);
        return $state;
    }

    private static function pkcs7Pad(string $data): string {
        $pad = 16 - (strlen($data) % 16);
        return $data . str_repeat(chr($pad), $pad);
    }

    private static function pkcs7Unpad(string $data): string {
        $pad = ord($data[strlen($data) - 1]);
        if ($pad < 1 || $pad > 16) throw new \RuntimeException('Invalid padding');
        return substr($data, 0, -$pad);
    }

    private static function xorBlocks(string $a, string $b): string {
        $result = '';
        for ($i = 0; $i < strlen($a); $i++) {
            $result .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $result;
    }

    private function gcmInc32(string $block): string {
        $result = $block;
        for ($i = 15; $i >= 12; $i--) {
            $v = (ord($result[$i]) + 1) & 0xff;
            $result[$i] = chr($v);
            if ($v !== 0) break;
        }
        return $result;
    }

    private function gcmMul(string $x, string $y): string {
        $z = str_repeat("\x00", 16);
        $v = $y;
        for ($i = 0; $i < 128; $i++) {
            $bit = (ord($x[intdiv($i, 8)]) >> (7 - ($i % 8))) & 1;
            if ($bit) $z = self::xorBlocks($z, $v);
            $lsb = ord($v[15]) & 1;
            $v = chr((ord($v[0]) >> 1) | (ord($v[1]) << 7)) .
                 chr((ord($v[1]) >> 1) | (ord($v[2]) << 7)) .
                 chr((ord($v[2]) >> 1) | (ord($v[3]) << 7)) .
                 chr((ord($v[3]) >> 1) | (ord($v[4]) << 7)) .
                 chr((ord($v[4]) >> 1) | (ord($v[5]) << 7)) .
                 chr((ord($v[5]) >> 1) | (ord($v[6]) << 7)) .
                 chr((ord($v[6]) >> 1) | (ord($v[7]) << 7)) .
                 chr((ord($v[7]) >> 1) | (ord($v[8]) << 7)) .
                 chr((ord($v[8]) >> 1) | (ord($v[9]) << 7)) .
                 chr((ord($v[9]) >> 1) | (ord($v[10]) << 7)) .
                 chr((ord($v[10]) >> 1) | (ord($v[11]) << 7)) .
                 chr((ord($v[11]) >> 1) | (ord($v[12]) << 7)) .
                 chr((ord($v[12]) >> 1) | (ord($v[13]) << 7)) .
                 chr((ord($v[13]) >> 1) | (ord($v[14]) << 7)) .
                 chr((ord($v[14]) >> 1) | (ord($v[15]) << 7)) .
                 chr((ord($v[15]) >> 1) | ($lsb << 7));
            if ($lsb) $v = self::xorBlocks($v, "\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        }
        return $z;
    }

    public function encryptECB(string $data): string {
        $data = self::pkcs7Pad($data);
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $result .= $this->encryptBlock(substr($data, $i, 16));
        }
        return $result;
    }

    public function decryptECB(string $data): string {
        if (strlen($data) % 16 !== 0) throw new \RuntimeException('Invalid ciphertext length');
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $result .= $this->decryptBlock(substr($data, $i, 16));
        }
        return self::pkcs7Unpad($result);
    }

    public function encryptCBC(string $data, string $iv): string {
        $data = self::pkcs7Pad($data);
        $result = '';
        $prev = $iv;
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $block = self::xorBlocks($block, $prev);
            $enc = $this->encryptBlock($block);
            $result .= $enc;
            $prev = $enc;
        }
        return $result;
    }

    public function decryptCBC(string $data, string $iv): string {
        if (strlen($data) % 16 !== 0) throw new \RuntimeException('Invalid ciphertext length');
        $result = '';
        $prev = $iv;
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $dec = $this->decryptBlock($block);
            $result .= self::xorBlocks($dec, $prev);
            $prev = $block;
        }
        return self::pkcs7Unpad($result);
    }

    public function encryptCFB(string $data, string $iv, int $segmentBits = 128): string {
        return $this->cfb($data, $iv, $segmentBits, true);
    }

    public function decryptCFB(string $data, string $iv, int $segmentBits = 128): string {
        return $this->cfb($data, $iv, $segmentBits, false);
    }

    private function cfb(string $data, string $iv, int $segmentBits, bool $encrypt): string {
        $segmentBytes = intdiv($segmentBits, 8);
        $result = '';
        $prev = $iv;
        for ($i = 0; $i < strlen($data); $i += $segmentBytes) {
            $enc = $this->encryptBlock($prev);
            $segment = substr($data, $i, $segmentBytes);
            $cipher = '';
            for ($j = 0; $j < strlen($segment); $j++) {
                $cipher .= chr(ord($segment[$j]) ^ ord($enc[$j]));
            }
            if ($encrypt) {
                $prev = $prev = substr($prev, $segmentBytes) . $cipher;
            } else {
                $prev = substr($prev, $segmentBytes) . $segment;
            }
            $result .= $cipher;
        }
        return $result;
    }

    public function encryptOFB(string $data, string $iv): string {
        $result = '';
        $feedback = $iv;
        for ($i = 0; $i < strlen($data); $i += 16) {
            $feedback = $this->encryptBlock($feedback);
            $block = substr($data, $i, 16);
            for ($j = 0; $j < strlen($block); $j++) {
                $result .= chr(ord($block[$j]) ^ ord($feedback[$j]));
            }
        }
        return $result;
    }

    public function decryptOFB(string $data, string $iv): string {
        return $this->encryptOFB($data, $iv);
    }

    public function encryptCTR(string $data, string $iv): string {
        $result = '';
        $counter = $iv;
        for ($i = 0; $i < strlen($data); $i += 16) {
            $enc = $this->encryptBlock($counter);
            $counter = $this->gcmInc32($counter);
            $block = substr($data, $i, 16);
            for ($j = 0; $j < strlen($block); $j++) {
                $result .= chr(ord($block[$j]) ^ ord($enc[$j]));
            }
        }
        return $result;
    }

    public function decryptCTR(string $data, string $iv): string {
        return $this->encryptCTR($data, $iv);
    }

    public function encryptGCM(string $data, string $iv, string $aad = '', int $tagLen = 16): array {
        $tagLen = min($tagLen, 16);
        $h = $this->encryptBlock(str_repeat("\x00", 16));
        $j0 = $iv . str_repeat("\x00", 4) . "\x00\x00\x00\x01";
        if (strlen($iv) === 12) {
            $j0 = $iv . "\x00\x00\x00\x01";
        } else {
            $s = 16 * (intdiv(strlen($iv) + 16 - 1, 16)) - strlen($iv);
            $hash = $iv . str_repeat("\x00", $s + 8) . pack('J', strlen($iv) * 8);
            $j0 = $this->gcmHash($hash, $h);
        }
        $ciphertext = $this->encryptGCMCTR($data, $j0);
        $s = 16 * (intdiv(strlen($aad) + 16 - 1, 16)) - strlen($aad);
        $s2 = 16 * (intdiv(strlen($ciphertext) + 16 - 1, 16)) - strlen($ciphertext);
        $hashData = $aad . str_repeat("\x00", $s) . $ciphertext . str_repeat("\x00", $s2) .
                    pack('J', strlen($aad) * 8) . pack('J', strlen($ciphertext) * 8);
        $sTag = $this->gcmHash($hashData, $h);
        $tagMask = $this->encryptBlock($j0);
        $tag = '';
        for ($i = 0; $i < $tagLen; $i++) {
            $tag .= chr(ord($sTag[$i]) ^ ord($tagMask[$i]));
        }
        return [$ciphertext, $tag];
    }

    private function encryptGCMCTR(string $data, string $icb): string {
        $result = '';
        $counter = $icb;
        for ($i = 0; $i < strlen($data); $i += 16) {
            $counter = $this->gcmInc32($counter);
            $enc = $this->encryptBlock($counter);
            $block = substr($data, $i, 16);
            for ($j = 0; $j < strlen($block); $j++) {
                $result .= chr(ord($block[$j]) ^ ord($enc[$j]));
            }
        }
        return $result;
    }

    private function gcmHash(string $data, string $h): string {
        $y = str_repeat("\x00", 16);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $y = self::xorBlocks($y, $block);
            $y = $this->gcmMul($y, $h);
        }
        return $y;
    }

    public function decryptGCM(string $data, string $iv, string $tag, string $aad = ''): string {
        $h = $this->encryptBlock(str_repeat("\x00", 16));
        $j0 = $iv . str_repeat("\x00", 4) . "\x00\x00\x00\x01";
        if (strlen($iv) === 12) {
            $j0 = $iv . "\x00\x00\x00\x01";
        } else {
            $s = 16 * (intdiv(strlen($iv) + 16 - 1, 16)) - strlen($iv);
            $hash = $iv . str_repeat("\x00", $s + 8) . pack('J', strlen($iv) * 8);
            $j0 = $this->gcmHash($hash, $h);
        }
        $plaintext = $this->encryptGCMCTR($data, $j0);
        $s = 16 * (intdiv(strlen($aad) + 16 - 1, 16)) - strlen($aad);
        $s2 = 16 * (intdiv(strlen($data) + 16 - 1, 16)) - strlen($data);
        $hashData = $aad . str_repeat("\x00", $s) . $data . str_repeat("\x00", $s2) .
                    pack('J', strlen($aad) * 8) . pack('J', strlen($data) * 8);
        $sTag = $this->gcmHash($hashData, $h);
        $tagMask = $this->encryptBlock($j0);
        $expectedTag = '';
        $tagLen = strlen($tag);
        for ($i = 0; $i < $tagLen; $i++) {
            $expectedTag .= chr(ord($sTag[$i]) ^ ord($tagMask[$i]));
        }
        if ($tag !== $expectedTag) {
            throw new \RuntimeException('GCM tag verification failed');
        }
        return $plaintext;
    }

    public function encryptCCM(string $data, string $iv, string $aad = '', int $tagLen = 8): array {
        $tagLen = min($tagLen, 16);
        $ivLen = 15 - intdiv($tagLen, 2);
        if ($ivLen < 2) $ivLen = 2;
        $nonce = substr($iv, 0, $ivLen);
        $flags = 0;
        if (strlen($aad) > 0) $flags |= 64;
        $flags |= (intdiv((intdiv($tagLen, 2) - 1), 2)) << 3;
        $flags |= ($ivLen - 1);
        $b0 = chr($flags) . $nonce . pack('J', strlen($data));
        $b0 = substr($b0, 0, 16);
        $blocks = [$b0];
        if (strlen($aad) > 0) {
            $la = strlen($aad);
            $ab = '';
            if ($la < 0xff00) $ab = pack('v', $la);
            else $ab = "\xff\xfe" . pack('J', $la);
            $ab .= $aad;
            while (strlen($ab) % 16 !== 0) $ab .= "\x00";
            for ($i = 0; $i < strlen($ab); $i += 16) $blocks[] = substr($ab, $i, 16);
        }
        $dataBlocks = [];
        for ($i = 0; $i < strlen($data); $i += 16) {
            $dataBlocks[] = str_pad(substr($data, $i, 16), 16, "\x00");
        }
        $ctr = 2;
        $ciphertext = '';
        foreach ($dataBlocks as $block) {
            $cipherBlock = $this->encryptBlock($block);
            $bCounter = chr(($flags & 0x07) | 0x10) . $nonce . pack('J', $ctr);
            $mask = $this->encryptBlock(str_pad($bCounter, 16, "\x00"));
            $ciphertext .= self::xorBlocks($cipherBlock, $mask);
            $ctr++;
        }
        $y = str_repeat("\x00", 16);
        foreach ($blocks as $block) {
            $y = $this->encryptBlock(self::xorBlocks($y, $block));
        }
        foreach ($dataBlocks as $i => $block) {
            $y = $this->encryptBlock(self::xorBlocks($y, $cipherBlock ?? $block));
        }
        $tag = substr($y, 0, $tagLen);
        $bCounter = chr(($flags & 0x07)) . $nonce . pack('J', 0);
        $mask = $this->encryptBlock(str_pad($bCounter, 16, "\x00"));
        for ($i = 0; $i < $tagLen; $i++) {
            $tag[$i] = chr(ord($tag[$i]) ^ ord($mask[$i]));
        }
        return [substr($ciphertext, 0, strlen($data)), $tag];
    }

    // Simplified CCM decrypt
    public function decryptCCM(string $data, string $iv, string $tag, string $aad = '', int $tagLen = 8): string {
        $result = $this->encryptCCM($data, $iv, $aad, $tagLen);
        return $result[0];
    }

    public function encryptEAX(string $data, string $iv): string {
        $nonceTag = $this->omac(0, $iv);
        $dataTag = $this->omac(1, $data);
        $ct = $this->encryptCTR($data, $nonceTag);
        $tag = $this->omac(2, '');
        for ($i = 0; $i < 16; $i++) {
            $tag[$i] = chr(ord($nonceTag[$i]) ^ ord($dataTag[$i]) ^ ord($tag[$i]));
        }
        return $ct . $tag;
    }

    public function decryptEAX(string $data, string $iv): string {
        $tag = substr($data, -16);
        $ct = substr($data, 0, -16);
        $nonceTag = $this->omac(0, $iv);
        $result = $this->encryptCTR($ct, $nonceTag);
        $dataTag = $this->omac(1, $result);
        $check = $this->omac(2, '');
        for ($i = 0; $i < 16; $i++) {
            $check[$i] = chr(ord($nonceTag[$i]) ^ ord($dataTag[$i]) ^ ord($check[$i]));
        }
        return $result;
    }

    private function omac(int $flag, string $data): string {
        $const = str_repeat("\x00", 15) . chr($flag);
        $block = $this->encryptBlock($const);
        $data = self::pkcs7Pad($data);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $b = substr($data, $i, 16);
            $block = $this->encryptBlock(self::xorBlocks($block, $b));
        }
        return $block;
    }

    public function encryptXTS(string $data, string $iv, int $dataUnit = 0): string {
        $tweak = $iv;
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $tweakE = $this->encryptBlock($tweak);
            $block = substr($data, $i, 16);
            $block = self::xorBlocks($block, $tweakE);
            $block = $this->encryptBlock($block);
            $block = self::xorBlocks($block, $tweakE);
            $result .= $block;
            $tweak = $this->xtsTweakMul($tweak);
        }
        return $result;
    }

    public function decryptXTS(string $data, string $iv, int $dataUnit = 0): string {
        $tweak = $iv;
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $tweakE = $this->encryptBlock($tweak);
            $block = substr($data, $i, 16);
            $block = self::xorBlocks($block, $tweakE);
            $block = $this->decryptBlock($block);
            $block = self::xorBlocks($block, $tweakE);
            $result .= $block;
            $tweak = $this->xtsTweakMul($tweak);
        }
        return $result;
    }

    private function xtsTweakMul(string $tweak): string {
        $carry = ord($tweak[0]) >> 7;
        $result = '';
        for ($i = 0; $i < 15; $i++) {
            $result .= chr(((ord($tweak[$i]) << 1) | (ord($tweak[$i + 1]) >> 7)) & 0xff);
        }
        $result .= chr((ord($tweak[15]) << 1) & 0xff);
        if ($carry) $result = self::xorBlocks($result, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87");
        return $result;
    }

    public function encryptPCBC(string $data, string $iv): string {
        $data = self::pkcs7Pad($data);
        $result = '';
        $prev = $iv;
        $prevPlain = str_repeat("\x00", 16);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $xored = self::xorBlocks(self::xorBlocks($block, $prevPlain), $prev);
            $enc = $this->encryptBlock($xored);
            $result .= $enc;
            $prevPlain = $block;
            $prev = $enc;
        }
        return $result;
    }

    public function decryptPCBC(string $data, string $iv): string {
        if (strlen($data) % 16 !== 0) throw new \RuntimeException('Invalid ciphertext length');
        $result = '';
        $prev = $iv;
        $prevPlain = str_repeat("\x00", 16);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $dec = $this->decryptBlock($block);
            $plain = self::xorBlocks(self::xorBlocks($dec, $prevPlain), $prev);
            $result .= $plain;
            $prevPlain = $plain;
            $prev = $block;
        }
        return self::pkcs7Unpad($result);
    }

    public function encryptIGE(string $data, string $iv): string {
        if (strlen($iv) !== 32) throw new \InvalidArgumentException('IGE IV must be 32 bytes');
        $data = self::pkcs7Pad($data);
        $xPrev = substr($iv, 0, 16);
        $yPrev = substr($iv, 16, 16);
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $xored = self::xorBlocks($block, $yPrev);
            $enc = $this->encryptBlock($xored);
            $cipher = self::xorBlocks($enc, $xPrev);
            $result .= $cipher;
            $xPrev = $block;
            $yPrev = $cipher;
        }
        return $result;
    }

    public function decryptIGE(string $data, string $iv): string {
        if (strlen($iv) !== 32) throw new \InvalidArgumentException('IGE IV must be 32 bytes');
        if (strlen($data) % 16 !== 0) throw new \RuntimeException('Invalid ciphertext length');
        $xPrev = substr($iv, 0, 16);
        $yPrev = substr($iv, 16, 16);
        $result = '';
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $xored = self::xorBlocks($block, $xPrev);
            $dec = $this->decryptBlock($xored);
            $plain = self::xorBlocks($dec, $yPrev);
            $result .= $plain;
            $xPrev = $block;
            $yPrev = $plain;
        }
        return self::pkcs7Unpad($result);
    }

    public function encryptBiIGE(string $data, string $iv): string {
        return $this->encryptIGE($data, $iv);
    }

    public function decryptBiIGE(string $data, string $iv): string {
        return $this->decryptIGE($data, $iv);
    }

    // AES Key Wrap (RFC 3394)
    private static function xor64(string $a, int $t): string {
        $result = '';
        for ($k = 7; $k >= 0; $k--) {
            $result = chr(ord($a[$k]) ^ ($t & 0xff)) . $result;
            $t >>= 8;
        }
        return $result;
    }

    public function wrapKey(string $key): string {
        $n = intdiv(strlen($key), 8);
        $a = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";
        $r = [];
        for ($i = 0; $i < $n; $i++) {
            $r[$i] = substr($key, $i * 8, 8);
        }
        for ($j = 0; $j < 6; $j++) {
            for ($i = 0; $i < $n; $i++) {
                $b = $this->encryptBlock($a . $r[$i]);
                $t = $n * $j + $i + 1;
                $a = self::xor64(substr($b, 0, 8), $t);
                $r[$i] = substr($b, 8, 8);
            }
        }
        $result = $a;
        for ($i = 0; $i < $n; $i++) $result .= $r[$i];
        return $result;
    }

    public function unwrapKey(string $data): string {
        $n = intdiv(strlen($data) - 8, 8);
        $a = substr($data, 0, 8);
        $r = [];
        for ($i = 0; $i < $n; $i++) {
            $r[$i] = substr($data, 8 + $i * 8, 8);
        }
        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n - 1; $i >= 0; $i--) {
                $t = $n * $j + $i + 1;
                $b = $this->decryptBlock(self::xor64($a, $t) . $r[$i]);
                $a = substr($b, 0, 8);
                $r[$i] = substr($b, 8, 8);
            }
        }
        $result = '';
        for ($i = 0; $i < $n; $i++) $result .= $r[$i];
        return $result;
    }

    // CMAC
    public function cmac(string $data): string {
        $k1 = $this->encryptBlock(str_repeat("\x00", 16));
        $k2 = $this->cmacSubkey($k1);
        $blocks = [];
        for ($i = 0; $i < strlen($data); $i += 16) {
            $blocks[] = substr($data, $i, 16);
        }
        $lastIdx = count($blocks) - 1;
        if (strlen($data) % 16 !== 0 || strlen($data) === 0) {
            $last = str_pad($blocks[$lastIdx] ?? '', 16, "\x00");
            $last[strlen($blocks[$lastIdx] ?? '')] = "\x80";
            $blocks[$lastIdx] = self::xorBlocks($last, $k2);
        } else {
            $blocks[$lastIdx] = self::xorBlocks($blocks[$lastIdx], $k1);
        }
        $x = str_repeat("\x00", 16);
        foreach ($blocks as $block) {
            $x = $this->encryptBlock(self::xorBlocks($x, $block));
        }
        return $x;
    }

    private function cmacSubkey(string $k): string {
        $lsb = ord($k[0]) >> 7;
        $result = '';
        for ($i = 0; $i < 15; $i++) {
            $result .= chr(((ord($k[$i]) << 1) | (ord($k[$i + 1]) >> 7)) & 0xff);
        }
        $result .= chr((ord($k[15]) << 1) & 0xff);
        if ($lsb) $result = self::xorBlocks($result, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87");
        return $result;
    }

    // Convenience method
    public function encrypt(string $data, string $mode, string $iv = '', string $aad = ''): string|array {
        return match (strtoupper($mode)) {
            'ECB' => $this->encryptECB($data),
            'CBC' => $this->encryptCBC($data, $iv),
            'CFB', 'CFB1', 'CFB8', 'CFB128' => $this->encryptCFB($data, $iv, (int)substr($mode, 3) ?: 128),
            'OFB' => $this->encryptOFB($data, $iv),
            'CTR' => $this->encryptCTR($data, $iv),
            'GCM' => $this->encryptGCM($data, $iv, $aad),
            'CCM' => $this->encryptCCM($data, $iv, $aad),
            'EAX' => $this->encryptEAX($data, $iv),
            'XTS' => $this->encryptXTS($data, $iv),
            'PCBC' => $this->encryptPCBC($data, $iv),
            'IGE' => $this->encryptIGE($data, $iv),
            default => throw new \InvalidArgumentException("Unknown mode: $mode")
        };
    }

    public function decrypt(string $data, string $mode, string $iv = '', string $aad = '', string $tag = ''): string|array {
        return match (strtoupper($mode)) {
            'ECB' => $this->decryptECB($data),
            'CBC' => $this->decryptCBC($data, $iv),
            'CFB', 'CFB1', 'CFB8', 'CFB128' => $this->decryptCFB($data, $iv, (int)substr($mode, 3) ?: 128),
            'OFB' => $this->decryptOFB($data, $iv),
            'CTR' => $this->decryptCTR($data, $iv),
            'GCM' => $this->decryptGCM($data, $iv, $tag, $aad),
            'CCM' => $this->decryptCCM($data, $iv, $tag, $aad),
            'EAX' => $this->decryptEAX($data, $iv),
            'XTS' => $this->decryptXTS($data, $iv),
            'PCBC' => $this->decryptPCBC($data, $iv),
            'IGE' => $this->decryptIGE($data, $iv),
            default => throw new \InvalidArgumentException("Unknown mode: $mode")
        };
    }
}
