<?php
declare(strict_types=1);
namespace FoxyCryptLib\Hash;

class HMAC {
    private const BLOCK_SIZES = [
        'md5'       => 64,
        'sha1'      => 64,
        'sha224'    => 64,
        'sha256'    => 64,
        'sha384'    => 128,
        'sha512'    => 128,
        'sha512224' => 128,
        'sha512256' => 128,
        'sha3224'   => 144,
        'sha3256'   => 136,
        'sha3384'   => 104,
        'sha3512'   => 72,
        'ripemd128' => 64,
        'ripemd160' => 64,
        'ripemd256' => 64,
        'ripemd320' => 64,
        'blake2b'   => 128,
        'blake2s'   => 64,
        'sm3'       => 64,
    ];

    private const METHOD_MAP = [
        'md5'       => 'md5',
        'sha1'      => 'sha1',
        'sha224'    => 'sha224',
        'sha256'    => 'sha256',
        'sha384'    => 'sha384',
        'sha512'    => 'sha512',
        'sha512224' => 'sha512_224',
        'sha512256' => 'sha512_256',
        'sha3224'   => 'sha3_224',
        'sha3256'   => 'sha3_256',
        'sha3384'   => 'sha3_384',
        'sha3512'   => 'sha3_512',
        'ripemd128' => 'ripemd128',
        'ripemd160' => 'ripemd160',
        'ripemd256' => 'ripemd256',
        'ripemd320' => 'ripemd320',
        'blake2b'   => 'blake2b',
        'blake2s'   => 'blake2s',
        'sm3'       => 'sm3',
    ];

    public static function hash(string $algo, string $data, string $key): string {
        $algo = str_replace(['-', '/'], '', strtolower($algo));
        if (!isset(self::METHOD_MAP[$algo])) {
            throw new \InvalidArgumentException("Unsupported HMAC algorithm: $algo");
        }
        $method = self::METHOD_MAP[$algo];
        $block = self::BLOCK_SIZES[$algo];
        $hashFn = [\FoxyCryptLib\Hash::class, $method];

        if (strlen($key) > $block) {
            $key = hex2bin($hashFn($key));
        }
        $key = str_pad($key, $block, "\x00");

        $ipad = $key ^ str_repeat("\x36", $block);
        $opad = $key ^ str_repeat("\x5c", $block);

        return $hashFn($opad . hex2bin($hashFn($ipad . $data)));
    }
}