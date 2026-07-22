<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class BigInt {
    private \GMP $value;

    public function __construct(string $limbs = '', bool $negative = false) {
        if ($limbs === '') {
            $this->value = gmp_init(0);
        } else {
            $be = strrev($limbs);
            $this->value = gmp_import($be);
            if ($negative) $this->value = gmp_neg($this->value);
        }
    }

    public function isZero(): bool { return gmp_cmp($this->value, 0) === 0; }
    public function isOne(): bool { return gmp_cmp($this->value, 1) === 0; }
    public function isNegative(): bool { return gmp_sign($this->value) < 0; }
    public function sign(): int { return gmp_sign($this->value); }

    public function bitLength(): int {
        if ($this->isZero()) return 0;
        return strlen(gmp_strval(gmp_abs($this->value), 2));
    }

    public function toBytes(): string {
        if ($this->isZero()) return '';
        return gmp_export(gmp_abs($this->value));
    }

    public static function fromBytes(string $bytes, bool $negative = false): self {
        if ($bytes === '') return new self();
        $val = new self();
        $val->value = gmp_import($bytes);
        if ($negative) $val->value = gmp_neg($val->value);
        return $val;
    }

    public static function fromHex(string $hex): self {
        if (preg_match('/^-?([0-9a-fA-F]+)$/', $hex, $m) !== 1) {
            throw new \InvalidArgumentException('Invalid hex: ' . $hex);
        }
        $val = new self();
        $val->value = gmp_init($hex, 16);
        return $val;
    }

    public function toHex(): string {
        if ($this->isZero()) return '0';
        return gmp_strval($this->value, 16);
    }

    public static function fromDec(string $dec): self {
        if (preg_match('/^-?[0-9]+$/', $dec) !== 1) throw new \InvalidArgumentException('Invalid decimal');
        $val = new self();
        $val->value = gmp_init($dec, 10);
        return $val;
    }

    public function toDec(): string {
        return gmp_strval($this->value, 10);
    }

    public static function fromInt(int $val): self {
        $obj = new self();
        $obj->value = gmp_init($val);
        return $obj;
    }

    public function toInt(): int {
        return gmp_intval($this->value);
    }

    public function compare(self $other): int {
        return gmp_cmp($this->value, $other->value);
    }

    public function equals(self $other): bool { return $this->compare($other) === 0; }

    public function abs(): self {
        $val = new self();
        $val->value = gmp_abs($this->value);
        return $val;
    }

    public function negate(): self {
        $val = new self();
        $val->value = gmp_neg($this->value);
        return $val;
    }

    public function add(self $other): self {
        $val = new self();
        $val->value = gmp_add($this->value, $other->value);
        return $val;
    }

    public function sub(self $other): self {
        $val = new self();
        $val->value = gmp_sub($this->value, $other->value);
        return $val;
    }

    public function addInt(int $val): self {
        return $this->add(self::fromInt($val));
    }

    public function mulInt(int $val): self {
        return $this->multiply(self::fromInt($val));
    }

    public function multiply(self $other): self {
        $val = new self();
        $val->value = gmp_mul($this->value, $other->value);
        return $val;
    }

    public function mul(self $other): self { return $this->multiply($other); }

    public function divMod(self $other): array {
        if ($other->isZero()) throw new \DivisionByZeroError('Division by zero');
        $q = gmp_div_q($this->value, $other->value, GMP_ROUND_ZERO);
        $r = gmp_sub($this->value, gmp_mul($q, $other->value));
        $qObj = new self(); $qObj->value = $q;
        $rObj = new self(); $rObj->value = $r;
        return [$qObj, $rObj];
    }

    public function divide(self $other): self {
        $val = new self();
        $val->value = gmp_div_q($this->value, $other->value, GMP_ROUND_ZERO);
        return $val;
    }

    public function mod(self $other): self {
        $val = new self();
        $val->value = gmp_mod($this->value, $other->value);
        return $val;
    }

    public function modSmall(int $divisor): int {
        return gmp_intval(gmp_mod($this->value, gmp_init($divisor)));
    }

    public function shiftLeft(int $bits): self {
        $val = new self();
        $val->value = gmp_mul($this->value, gmp_pow(gmp_init(2), $bits));
        return $val;
    }

    public function shiftRight(int $bits): self {
        $val = new self();
        $val->value = gmp_div_q($this->value, gmp_pow(gmp_init(2), $bits), GMP_ROUND_ZERO);
        return $val;
    }

    public function and(self $other): self {
        $val = new self();
        $val->value = gmp_and($this->value, $other->value);
        return $val;
    }

    public function or(self $other): self {
        $val = new self();
        $val->value = gmp_or($this->value, $other->value);
        return $val;
    }

    public function xor(self $other): self {
        $val = new self();
        $val->value = gmp_xor($this->value, $other->value);
        return $val;
    }

    public function powMod(self $exp, self $mod): self {
        $val = new self();
        $val->value = gmp_powm($this->value, $exp->value, $mod->value);
        return $val;
    }

    public function gcd(self $other): self {
        $val = new self();
        $val->value = gmp_gcd($this->value, $other->value);
        return $val;
    }

    public function extendedGcd(self $other): array {
        $g = gmp_gcdext($this->value, $other->value);
        $gObj = new self(); $gObj->value = $g['g'];
        $sObj = new self(); $sObj->value = $g['s'];
        $tObj = new self(); $tObj->value = $g['t'];
        return [$gObj, $sObj, $tObj];
    }

    public function modInverse(self $mod): self {
        $inv = gmp_invert($this->value, $mod->value);
        if ($inv === false) {
            throw new \RuntimeException('Modular inverse does not exist');
        }
        $val = new self();
        $val->value = $inv;
        return $val;
    }

    public function isEven(): bool {
        return gmp_testbit($this->value, 0) === false;
    }

    public function isPrime(int $rounds = 5): bool {
        return gmp_prob_prime($this->value, $rounds) > 0;
    }

    public static function randomBits(int $bits): self {
        $val = new self();
        $val->value = gmp_random_bits($bits);
        return $val;
    }

    public static function randomRange(self $min, self $max): self {
        $val = new self();
        $val->value = gmp_random_range($min->value, $max->value);
        return $val;
    }

    public static function randomPrime(int $bits, int $rounds = 10): self {
        while (true) {
            $candidate = self::randomBits($bits);
            $candidate = $candidate->or(self::fromInt(1));
            if (gmp_prob_prime($candidate->value, $rounds)) return $candidate;
        }
    }

    public static function fromGMP(string $hex): self {
        return self::fromHex($hex);
    }

    public function __clone() {}

    public function __toString(): string {
        return $this->toHex();
    }
}
