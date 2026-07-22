<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class Hash {
    public static function md2(string $data): string { return bin2hex(Hash\MD5::md2($data)); }
    public static function md4(string $data): string { return bin2hex(Hash\MD5::md4($data)); }
    public static function md5(string $data): string { return bin2hex(Hash\MD5::hash($data)); }
    public static function sha0(string $data): string { return bin2hex(Hash\SHA1::sha0($data)); }
    public static function sha1(string $data): string { return bin2hex(Hash\SHA1::hash($data)); }
    public static function sha224(string $data): string { return bin2hex(Hash\SHA256::hash($data, true)); }
    public static function sha256(string $data): string { return bin2hex(Hash\SHA256::hash($data, false)); }
    public static function sha384(string $data): string { return bin2hex(Hash\SHA512::hash384($data)); }
    public static function sha512(string $data): string { return bin2hex(Hash\SHA512::hash512($data)); }
    public static function sha512_224(string $data): string { return bin2hex(Hash\SHA512::hash512_224($data)); }
    public static function sha512_256(string $data): string { return bin2hex(Hash\SHA512::hash512_256($data)); }
    public static function sha3_224(string $data): string { return bin2hex(Hash\SHA3::sha3_224($data)); }
    public static function sha3_256(string $data): string { return bin2hex(Hash\SHA3::sha3_256($data)); }
    public static function sha3_384(string $data): string { return bin2hex(Hash\SHA3::sha3_384($data)); }
    public static function sha3_512(string $data): string { return bin2hex(Hash\SHA3::sha3_512($data)); }
    public static function shake128(string $data, int $outputLen = 32): string { return bin2hex(Hash\SHA3::shake128($data, $outputLen)); }
    public static function shake256(string $data, int $outputLen = 32): string { return bin2hex(Hash\SHA3::shake256($data, $outputLen)); }
    public static function keccak224(string $data): string { return bin2hex(Hash\SHA3::keccak224($data)); }
    public static function keccak256(string $data): string { return bin2hex(Hash\SHA3::keccak256($data)); }
    public static function keccak384(string $data): string { return bin2hex(Hash\SHA3::keccak384($data)); }
    public static function keccak512(string $data): string { return bin2hex(Hash\SHA3::keccak512($data)); }
    public static function ripemd128(string $data): string { return bin2hex(Hash\RIPEMD::hash128($data)); }
    public static function ripemd160(string $data): string { return bin2hex(Hash\RIPEMD::hash160($data)); }
    public static function ripemd256(string $data): string { return bin2hex(Hash\RIPEMD::hash256($data)); }
    public static function ripemd320(string $data): string { return bin2hex(Hash\RIPEMD::hash320($data)); }
    public static function ripemd(string $data): string { return self::ripemd160($data); }
    public static function whirlpool(string $data): string { return bin2hex(Hash\Whirlpool::hash($data)); }
    public static function tiger(string $data): string { return bin2hex(Hash\Tiger::hash($data)); }
    public static function tiger2(string $data): string { return bin2hex(Hash\Tiger::hash($data)); }
    public static function gost(string $data): string { return bin2hex(Hash\GOST::hash94($data)); }
    public static function streebog256(string $data): string { return bin2hex(Hash\GOST::streebog256($data)); }
    public static function streebog512(string $data): string { return bin2hex(Hash\GOST::streebog512($data)); }
    public static function sm3(string $data): string { return bin2hex(Hash\SM3::hash($data)); }
    public static function blake2b(string $data, int $size = 64): string { return bin2hex(Hash\BLAKE2::hash($data, $size)); }
    public static function blake2s(string $data): string { return bin2hex(Hash\BLAKE2::hash($data, 32)); }
    public static function blake2bp(string $data): string { return self::blake2b($data, 64); }
    public static function blake2sp(string $data): string { return self::blake2s($data); }
    public static function crc8(string $data): string { return bin2hex(chr(Hash\FastHash::crc8($data))); }
    public static function crc16(string $data): string { return bin2hex(pack('v', Hash\FastHash::crc16($data))); }
    public static function crc24(string $data): string { return bin2hex(substr(pack('N', Hash\FastHash::crc24($data)), 1, 3)); }
    public static function crc32(string $data): string { return bin2hex(pack('V', Hash\FastHash::crc32($data))); }
    public static function crc32c(string $data): string { return bin2hex(pack('V', Hash\FastHash::crc32c($data))); }
    public static function crc64(string $data): string { return bin2hex(pack('J', Hash\FastHash::crc64($data))); }
    public static function adler32(string $data): string { return bin2hex(pack('V', Hash\FastHash::adler32($data))); }
    public static function fnv1(string $data): string { return bin2hex(pack('V', Hash\FastHash::fnv1($data))); }
    public static function fnv1a(string $data): string { return bin2hex(pack('V', Hash\FastHash::fnv1a($data))); }
    public static function djb2(string $data): string { return bin2hex(pack('V', Hash\FastHash::djb2($data))); }
    public static function sdbm(string $data): string { return bin2hex(pack('V', Hash\FastHash::sdbm($data))); }
    public static function jenkins(string $data): string { return bin2hex(pack('V', Hash\FastHash::jenkins($data))); }
    public static function pearson(string $data): string { return bin2hex(Hash\FastHash::pearson($data)); }
    public static function xxhash32(string $data): string { return bin2hex(pack('V', Hash\FastHash::xxhash32($data))); }
    public static function murmur2(string $data): string { return bin2hex(pack('V', Hash\FastHash::murmur2($data))); }
    public static function murmur3(string $data): string { return bin2hex(pack('V', Hash\FastHash::murmur3($data))); }
    public static function bsdm(string $data): string { return bin2hex(pack('v', Hash\FastHash::bsdm($data))); }
    public static function sysv(string $data): string { return bin2hex(pack('v', Hash\FastHash::sysv($data))); }

    public static function hash(string $algo, string $data): string {
        $algo = str_replace(['-', '/'], '', strtolower($algo));
        $map = [
            'md2'=>'md2','md4'=>'md4','md5'=>'md5','sha0'=>'sha0','sha1'=>'sha1',
            'sha224'=>'sha224','sha256'=>'sha256','sha384'=>'sha384','sha512'=>'sha512',
            'sha512224'=>'sha512_224','sha512256'=>'sha512_256','sha512_224'=>'sha512_224','sha512_256'=>'sha512_256',
            'sha3224'=>'sha3_224','sha3256'=>'sha3_256','sha3384'=>'sha3_384','sha3512'=>'sha3_512',
            'sha3_224'=>'sha3_224','sha3_256'=>'sha3_256','sha3_384'=>'sha3_384','sha3_512'=>'sha3_512',
            'shake128'=>'shake128','shake256'=>'shake256',
            'keccak224'=>'keccak224','keccak256'=>'keccak256','keccak384'=>'keccak384','keccak512'=>'keccak512',
            'ripemd128'=>'ripemd128','ripemd160'=>'ripemd160','ripemd256'=>'ripemd256','ripemd320'=>'ripemd320',
            'ripemd'=>'ripemd160','whirlpool'=>'whirlpool','tiger'=>'tiger','tiger2'=>'tiger2',
            'gost'=>'gost','gostr341194'=>'gost','streebog256'=>'streebog256','streebog512'=>'streebog512',
            'sm3'=>'sm3','blake2b'=>'blake2b','blake2s'=>'blake2s','blake2bp'=>'blake2bp','blake2sp'=>'blake2sp',
            'crc8'=>'crc8','crc16'=>'crc16','crc24'=>'crc24','crc32'=>'crc32','crc32c'=>'crc32c','crc64'=>'crc64',
            'adler32'=>'adler32','fnv1'=>'fnv1','fnv1a'=>'fnv1a','djb2'=>'djb2','sdbm'=>'sdbm',
            'jenkins'=>'jenkins','pearson'=>'pearson','xxhash32'=>'xxhash32',
            'murmur2'=>'murmur2','murmur3'=>'murmur3','bsdm'=>'bsdm','sysv'=>'sysv',
        ];
        if (!isset($map[$algo])) {
            throw new \InvalidArgumentException("Unknown hash algorithm: $algo");
        }
        return self::{$map[$algo]}($data);
    }

    public static function hmac(string $algo, string $data, string $key): string {
        return Hash\HMAC::hash($algo, $data, $key);
    }

    public static function pbkdf2(string $algo, string $pass, string $salt, int $iterations, int $keyLen): string {
        $hashLen = strlen(hex2bin(self::hash($algo, '')));
        $blocks = intdiv($keyLen + $hashLen - 1, $hashLen);
        $result = '';
        for ($i = 1; $i <= $blocks; $i++) {
            $u = $salt . pack('N', $i);
            $block = '';
            for ($j = 0; $j < $iterations; $j++) {
                $u = hex2bin(self::hmac($algo, $u, $pass));
                $block = $block === '' ? $u : ($block ^ $u);
            }
            $result .= $block;
        }
        return bin2hex(substr($result, 0, $keyLen));
    }
}
