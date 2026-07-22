<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class Accel {
    private static ?\FFI $bcrypt = null;
    private static bool $bcryptChecked = false;

    public static function isBCryptAvailable(): bool {
        if (!self::$bcryptChecked) {
            self::$bcryptChecked = true;
            try {
                self::$bcrypt = \FFI::cdef(
                    'int BCryptGenRandom(void*, unsigned char*, unsigned long, unsigned long);',
                    'bcrypt.dll'
                );
            } catch (\Throwable) {}
        }
        return self::$bcrypt !== null;
    }

    public static function randomBytes(int $count): ?string {
        if (!self::isBCryptAvailable()) return null;
        try {
            $buf = \FFI::new("unsigned char[$count]");
            $ret = self::$bcrypt->BCryptGenRandom(null, $buf, $count, 2);
            if ($ret === 0) {
                $data = \FFI::string($buf, $count);
                \FFI::free($buf);
                return $data;
            }
            \FFI::free($buf);
        } catch (\Throwable) {}
        return null;
    }

    public static function bigIntToGmp(BigInt $n): \GMP {
        $hex = $n->toHex();
        $neg = $hex[0] === '-';
        if ($neg) $hex = substr($hex, 1);
        $g = gmp_init($hex, 16);
        return $neg ? gmp_neg($g) : $g;
    }

    public static function gmpToBigInt(\GMP $g): BigInt {
        $hex = gmp_strval($g, 16);
        return BigInt::fromHex($hex);
    }

    public static function powMod(BigInt $base, BigInt $exp, BigInt $mod): BigInt {
        if (extension_loaded('gmp')) {
            $gb = self::bigIntToGmp($base);
            $ge = self::bigIntToGmp($exp);
            $gm = self::bigIntToGmp($mod);
            return self::gmpToBigInt(gmp_powm($gb, $ge, $gm));
        }
        return $base->powMod($exp, $mod);
    }

    public static function isPrime(BigInt $n, int $rounds = 5): bool {
        if ($n->compare(BigInt::fromInt(2)) < 0) return false;
        if ($n->isEven()) return $n->equals(BigInt::fromInt(2));
        if (extension_loaded('gmp')) {
            $g = self::bigIntToGmp($n);
            return gmp_prob_prime($g, $rounds) !== 0;
        }
        return $n->isPrime($rounds);
    }

    public static function modInverse(BigInt $a, BigInt $mod): BigInt {
        if (extension_loaded('gmp')) {
            $ga = self::bigIntToGmp($a);
            $gm = self::bigIntToGmp($mod);
            $r = gmp_invert($ga, $gm);
            if ($r === false) throw new \RuntimeException('Modular inverse does not exist');
            return self::gmpToBigInt($r);
        }
        return $a->modInverse($mod);
    }

    public static function multiply(BigInt $a, BigInt $b): BigInt {
        if (extension_loaded('gmp')) {
            $ga = self::bigIntToGmp($a);
            $gb = self::bigIntToGmp($b);
            return self::gmpToBigInt(gmp_mul($ga, $gb));
        }
        return $a->multiply($b);
    }

    public static function gcd(BigInt $a, BigInt $b): BigInt {
        if (extension_loaded('gmp')) {
            $ga = self::bigIntToGmp($a);
            $gb = self::bigIntToGmp($b);
            return self::gmpToBigInt(gmp_gcd($ga, $gb));
        }
        return $a->gcd($b);
    }

    public static function mod(BigInt $a, BigInt $mod): BigInt {
        if (extension_loaded('gmp')) {
            $ga = self::bigIntToGmp($a);
            $gm = self::bigIntToGmp($mod);
            return self::gmpToBigInt(gmp_mod($ga, $gm));
        }
        return $a->mod($mod);
    }

    public static function randomPrime(int $bits, int $rounds = 5): BigInt {
        if (extension_loaded('gmp')) {
            while (true) {
                $candidate = BigInt::randomBits($bits);
                $candidate = $candidate->or(BigInt::fromInt(1));
                if (self::isPrime($candidate, $rounds)) return $candidate;
            }
        }
        return BigInt::randomPrime($bits, $rounds);
    }
}
