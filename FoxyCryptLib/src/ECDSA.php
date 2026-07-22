<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class ECDSA {
    private ECC $curve;
    private ?BigInt $d;
    private ?BigInt $x;
    private ?BigInt $y;

    public function __construct(string $curveName = 'P-256') {
        $this->curve = new ECC($curveName);
    }

    public static function fromCurve(ECC $curve): self {
        $e = new self($curve->name);
        $e->curve = $curve;
        return $e;
    }

    public function getCurve(): ECC { return $this->curve; }

    public function generateKeys(): self {
        $kp = $this->curve->generateKeyPair();
        $this->d = $kp['d'];
        $this->x = $kp['x'];
        $this->y = $kp['y'];
        return $this;
    }

    public function setPrivateKey(BigInt $d): self {
        $this->d = $d;
        [$this->x, $this->y] = ECC::pointMultiply($d, $this->curve->gx, $this->curve->gy, $this->curve->p, $this->curve->a);
        return $this;
    }

    public function setPublicKey(BigInt $x, BigInt $y): self {
        $this->x = $x;
        $this->y = $y;
        return $this;
    }

    public function getPrivateKey(): ?BigInt { return $this->d; }
    public function getPublicKey(): array { return ['x' => $this->x, 'y' => $this->y]; }

    public function sign(string $data): string {
        if (!$this->d) throw new \RuntimeException('Private key required for signing');
        $e = hex2bin(Hash::hash($this->curve->hashAlgo, $data));
        $z = BigInt::fromBytes($e);
        $orderBits = $this->curve->n->bitLength();
        $orderBytes = intdiv($orderBits + 7, 8);
        if (strlen($e) > $orderBytes) $e = substr($e, 0, $orderBytes);
        $z = BigInt::fromBytes($e);
        $n = $this->curve->n;

        while (true) {
            $k = BigInt::randomRange(BigInt::fromInt(1), $n->sub(BigInt::fromInt(1)));
            [$rX] = ECC::pointMultiply($k, $this->curve->gx, $this->curve->gy, $this->curve->p, $this->curve->a);
            $r = $rX->mod($n);
            if ($r->isZero()) continue;

            $s = $k->modInverse($n)->multiply($z->add($r->multiply($this->d)->mod($n)))->mod($n);
            if ($s->isZero()) continue;

            return DER::encodeSequence([
                DER::encodeInteger($r->toBytes()),
                DER::encodeInteger($s->toBytes())
            ]);
        }
    }

    public function verify(string $data, string $signature): bool {
        if (!$this->x || !$this->y) throw new \RuntimeException('Public key required for verification');
        $parsed = DER::parse($signature);
        $r = BigInt::fromBytes($parsed['children'][0]['data']);
        $s = BigInt::fromBytes($parsed['children'][1]['data']);
        $n = $this->curve->n;

        if ($r->compare(BigInt::fromInt(1)) < 0 || $r->compare($n->sub(BigInt::fromInt(1))) > 0) return false;
        if ($s->compare(BigInt::fromInt(1)) < 0 || $s->compare($n->sub(BigInt::fromInt(1))) > 0) return false;

        $e = hex2bin(Hash::hash($this->curve->hashAlgo, $data));
        $orderBits = $n->bitLength();
        $orderBytes = intdiv($orderBits + 7, 8);
        if (strlen($e) > $orderBytes) $e = substr($e, 0, $orderBytes);
        $z = BigInt::fromBytes($e);

        $w = $s->modInverse($n);
        $u1 = $z->multiply($w)->mod($n);
        $u2 = $r->multiply($w)->mod($n);

        $p1 = ECC::pointMultiply($u1, $this->curve->gx, $this->curve->gy, $this->curve->p, $this->curve->a);
        $p2 = ECC::pointMultiply($u2, $this->x, $this->y, $this->curve->p, $this->curve->a);
        [$xp] = ECC::pointAdd($p1[0], $p1[1], $p2[0], $p2[1], $this->curve->p, $this->curve->a);

        if ($xp === null) return false;
        return $r->equals($xp->mod($n));
    }

    public function getPublicKeyPEM(): string {
        if (!$this->x || !$this->y) throw new \RuntimeException('Public key not available');
        return $this->curve->getPublicKeyPEM($this->x, $this->y);
    }

    public function getPrivateKeyPEM(): string {
        if (!$this->d) throw new \RuntimeException('Private key not available');
        return $this->curve->getPrivateKeyPEM($this->d, $this->x, $this->y);
    }

    public static function fromPEM(string $pem): self {
        if (str_contains($pem, 'EC PRIVATE KEY')) {
            $info = ECC::pemToPrivateKey($pem);
            $e = self::fromCurve($info['curve']);
            $e->d = $info['d'];
            $e->x = $info['x'];
            $e->y = $info['y'];
            return $e;
        }
        $info = ECC::pemToPublicKey($pem);
        $e = self::fromCurve($info['curve']);
        $e->x = $info['x'];
        $e->y = $info['y'];
        return $e;
    }
}
