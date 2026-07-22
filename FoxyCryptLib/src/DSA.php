<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class DSA {
    private BigInt $p;
    private BigInt $q;
    private BigInt $g;
    private BigInt $y;
    private ?BigInt $x;
    private int $keySize;

    public function __construct(int $keySize = 2048) {
        $this->keySize = $keySize;
    }

    public function generateKeys(): self {
        $qBits = match(true) {
            $this->keySize >= 2048 => 256,
            $this->keySize >= 1024 => 160,
            default => 160
        };
        $this->q = BigInt::randomPrime($qBits);
        $rem = $this->keySize - $qBits;
        $r = $rem > 0 ? $rem : 160;
        $counter = 0;
        do {
            $seed = Random::bytes(intdiv($r + 7, 8));
            $seedHash = hex2bin(Hash::sha256($seed));
            $seedMinus = BigInt::fromBytes($seed)->sub(BigInt::fromInt(1))->toBytes();
            $seedHash2 = hex2bin(Hash::sha256($seedMinus));
            $v = BigInt::fromBytes($seedHash ^ $seedHash2);
            $v = $v->or(BigInt::fromInt(1)->shiftLeft($r - 1));
            $p = $v->sub($v->mod($this->q->multiply(BigInt::fromInt(2))))->add($this->q);
            $counter++;
        } while (!$p->isPrime() && $counter < 100);

        $this->p = $p;
        $h = BigInt::fromInt(2);
        $exp = $this->p->sub($this->q)->divide($this->q);
        $this->g = $h->powMod($exp, $this->p);
        while ($this->g->isOne()) {
            $h = $h->add(BigInt::fromInt(1));
            $this->g = $h->powMod($exp, $this->p);
        }
        $this->x = BigInt::randomRange(BigInt::fromInt(1), $this->q->sub(BigInt::fromInt(1)));
        $this->y = $this->g->powMod($this->x, $this->p);
        return $this;
    }

    public static function fromPublicKey(BigInt $p, BigInt $q, BigInt $g, BigInt $y): self {
        $dsa = new self($p->bitLength());
        $dsa->p = $p; $dsa->q = $q; $dsa->g = $g; $dsa->y = $y;
        return $dsa;
    }

    public static function fromPrivateKey(BigInt $p, BigInt $q, BigInt $g, BigInt $y, BigInt $x): self {
        $dsa = self::fromPublicKey($p, $q, $g, $y);
        $dsa->x = $x;
        return $dsa;
    }

    public static function fromPEM(string $pem): self {
        $info = PEM::decode($pem);
        $label = $info['label'];
        if (str_contains($label, 'PRIVATE KEY')) {
            $key = PEM::pemToDSAPrivateKey($pem);
            return self::fromPrivateKey($key['p'], $key['q'], $key['g'], $key['y'], $key['x']);
        } else {
            $key = PEM::pemToDSAPublicKey($pem);
            return self::fromPublicKey($key['p'], $key['q'], $key['g'], $key['y']);
        }
    }

    public function getPublicKeyPEM(): string {
        return PEM::dsaPublicKeyToPEM(
            $this->p->toBytes(), $this->q->toBytes(),
            $this->g->toBytes(), $this->y->toBytes()
        );
    }

    public function getPrivateKeyPEM(): string {
        if (!$this->x) throw new \RuntimeException('Private key not available');
        return PEM::dsaPrivateKeyToPEM(
            $this->p->toBytes(), $this->q->toBytes(),
            $this->g->toBytes(), $this->y->toBytes(),
            $this->x->toBytes()
        );
    }

    public function sign(string $data): string {
        if (!$this->x) throw new \RuntimeException('Private key required for signing');
        $hash = hex2bin(Hash::sha256($data));
        $hashInt = BigInt::fromBytes($hash);
        $hashInt = $hashInt->mod($this->q);
        $k = BigInt::randomRange(BigInt::fromInt(1), $this->q->sub(BigInt::fromInt(1)));
        $r = $this->g->powMod($k, $this->p)->mod($this->q);
        $s = $k->modInverse($this->q)->multiply($hashInt->add($this->x->multiply($r)->mod($this->q)))->mod($this->q);
        if ($r->isZero() || $s->isZero()) {
            return $this->sign($data);
        }
        $rBytes = $r->toBytes();
        $sBytes = $s->toBytes();
        $qBytes = strlen($this->q->toBytes());
        while (strlen($rBytes) < $qBytes) $rBytes = "\x00" . $rBytes;
        while (strlen($sBytes) < $qBytes) $sBytes = "\x00" . $sBytes;
        return DER::encodeSequence([
            DER::encodeInteger($rBytes),
            DER::encodeInteger($sBytes)
        ]);
    }

    public function verify(string $data, string $signature): bool {
        $parsed = DER::parse($signature);
        $r = BigInt::fromBytes($parsed['children'][0]['data']);
        $s = BigInt::fromBytes($parsed['children'][1]['data']);
        if ($r->compare(BigInt::fromInt(1)) < 0 || $r->compare($this->q->sub(BigInt::fromInt(1))) > 0) return false;
        if ($s->compare(BigInt::fromInt(1)) < 0 || $s->compare($this->q->sub(BigInt::fromInt(1))) > 0) return false;
        $hash = hex2bin(Hash::sha256($data));
        $hashInt = BigInt::fromBytes($hash);
        $hashInt = $hashInt->mod($this->q);
        $w = $s->modInverse($this->q);
        $u1 = $hashInt->multiply($w)->mod($this->q);
        $u2 = $r->multiply($w)->mod($this->q);
        $v1 = $this->g->powMod($u1, $this->p);
        $v2 = $this->y->powMod($u2, $this->p);
        $v = $v1->multiply($v2)->mod($this->p)->mod($this->q);
        return $v->equals($r);
    }
}
