<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class RSA {
    private BigInt $n;
    private BigInt $e;
    private ?BigInt $d;
    private ?BigInt $p;
    private ?BigInt $q;
    private ?BigInt $dp;
    private ?BigInt $dq;
    private ?BigInt $qi;
    private int $keySize;

    public function __construct(int $keySize = 2048) {
        $this->keySize = $keySize;
    }

    public function generateKeys(): self {
        $halfBits = intdiv($this->keySize, 2);
        $p = BigInt::randomPrime($halfBits);
        $q = BigInt::randomPrime($this->keySize - $halfBits);
        if ($p->compare($q) === 0) {
            $q = BigInt::randomPrime($this->keySize - $halfBits);
        }
        $this->n = $p->multiply($q);
        $p1 = $p->sub(BigInt::fromInt(1));
        $q1 = $q->sub(BigInt::fromInt(1));
        $phi = $p1->multiply($q1);
        $this->e = BigInt::fromInt(65537);
        $this->d = $this->e->modInverse($phi);
        $this->p = $p;
        $this->q = $q;
        $this->dp = $this->d->mod($p1);
        $this->dq = $this->d->mod($q1);
        $this->qi = $q->modInverse($p);
        return $this;
    }

    public static function fromPublicKey(BigInt $n, BigInt $e): self {
        $rsa = new self($n->bitLength());
        $rsa->n = $n;
        $rsa->e = $e;
        $rsa->d = null;
        return $rsa;
    }

    public static function fromPrivateKey(BigInt $n, BigInt $e, BigInt $d, ?BigInt $p = null, ?BigInt $q = null): self {
        $rsa = new self($n->bitLength());
        $rsa->n = $n;
        $rsa->e = $e;
        $rsa->d = $d;
        $rsa->p = $p;
        $rsa->q = $q;
        if ($p && $q) {
            $p1 = $p->sub(BigInt::fromInt(1));
            $q1 = $q->sub(BigInt::fromInt(1));
            $rsa->dp = $d->mod($p1);
            $rsa->dq = $d->mod($q1);
            $rsa->qi = $q->modInverse($p);
        }
        return $rsa;
    }

    public static function fromPEM(string $pem): self {
        $info = PEM::decode($pem);
        $label = $info['label'];
        if (str_contains($label, 'PRIVATE KEY')) {
            $key = PEM::pemToRSAPrivateKey($pem);
            return self::fromPrivateKey($key['n'], $key['e'], $key['d'], $key['p'], $key['q']);
        } else {
            $key = PEM::pemToRSAPublicKey($pem);
            return self::fromPublicKey($key['n'], $key['e']);
        }
    }

    public function getPublicKeyPEM(): string {
        return PEM::rsaPublicKeyToPEM(
            $this->n->toBytes(),
            $this->e->toBytes()
        );
    }

    public function getPrivateKeyPEM(): string {
        if (!$this->d || !$this->p || !$this->q) {
            throw new \RuntimeException('Private key not available');
        }
        return PEM::rsaPrivateKeyToPEM(
            $this->n->toBytes(),
            $this->e->toBytes(),
            $this->d->toBytes(),
            $this->p->toBytes(),
            $this->q->toBytes(),
            $this->dp->toBytes(),
            $this->dq->toBytes(),
            $this->qi->toBytes()
        );
    }

    private function pkcs1EncryptPad(string $data, int $targetLen): string {
        $maxDataLen = $targetLen - 11;
        if (strlen($data) > $maxDataLen) {
            throw new \RuntimeException('Data too long for PKCS#1 padding');
        }
        $paddingLen = $targetLen - strlen($data) - 3;
        $padding = '';
        while (strlen($padding) < $paddingLen) {
            $byte = chr(Random::int(1, 255));
            if ($byte !== "\x00") $padding .= $byte;
        }
        return "\x00\x02" . $padding . "\x00" . $data;
    }

    private function pkcs1SignPad(string $data, int $targetLen, string $hashAlgo): string {
        $digestInfo = DER::encodeDigestInfo($data, $hashAlgo);
        $maxDataLen = $targetLen - 11;
        if (strlen($digestInfo) > $maxDataLen) {
            throw new \RuntimeException('Data too long for PKCS#1 signature padding');
        }
        $paddingLen = $targetLen - strlen($digestInfo) - 3;
        return "\x00\x01" . str_repeat("\xff", $paddingLen) . "\x00" . $digestInfo;
    }

    private function pkcs1Unpad(string $data): string {
        if (strlen($data) < 11) throw new \RuntimeException('Invalid PKCS#1 padding');
        if ($data[0] !== "\x00") throw new \RuntimeException('Invalid block type');
        if ($data[1] !== "\x02" && $data[1] !== "\x01") throw new \RuntimeException('Unknown padding type');
        $pos = strpos($data, "\x00", 2);
        if ($pos === false || $pos < 10) throw new \RuntimeException('Invalid padding');
        return substr($data, $pos + 1);
    }

    public function encrypt(string $data): string {
        $keyBytes = strlen($this->n->toBytes());
        $padded = $this->pkcs1EncryptPad($data, $keyBytes);
        $m = BigInt::fromBytes($padded);
        $c = Accel::powMod($m, $this->e, $this->n);
        $result = $c->toBytes();
        while (strlen($result) < $keyBytes) $result = "\x00" . $result;
        return $result;
    }

    public function decrypt(string $data): string {
        if (!$this->d) throw new \RuntimeException('Private key required for decryption');
        $keyBytes = strlen($this->n->toBytes());
        $c = BigInt::fromBytes($data);
        if ($this->p && $this->q) {
            $m1 = Accel::powMod($c, $this->dp, $this->p);
            $m2 = Accel::powMod($c, $this->dq, $this->q);
            $h = $this->qi->multiply($m1->sub($m2)->mod($this->p))->mod($this->p);
            $m = $h->multiply($this->q)->add($m2);
        } else {
            $m = Accel::powMod($c, $this->d, $this->n);
        }
        $padded = $m->toBytes();
        while (strlen($padded) < $keyBytes) $padded = "\x00" . $padded;
        return $this->pkcs1Unpad($padded);
    }

    public function sign(string $data, string $hashAlgo = 'sha256'): string {
        if (!$this->d) throw new \RuntimeException('Private key required for signing');
        $keyBytes = strlen($this->n->toBytes());
        $padded = $this->pkcs1SignPad($data, $keyBytes, $hashAlgo);
        $m = BigInt::fromBytes($padded);
        $sig = Accel::powMod($m, $this->d, $this->n);
        $result = $sig->toBytes();
        while (strlen($result) < $keyBytes) $result = "\x00" . $result;
        return $result;
    }

    public function verify(string $data, string $signature, string $hashAlgo = 'sha256'): bool {
        $keyBytes = strlen($this->n->toBytes());
        if (strlen($signature) !== $keyBytes) return false;

        $sig = BigInt::fromBytes($signature);
        if ($sig->compare($this->n) >= 0) return false;

        $m = Accel::powMod($sig, $this->e, $this->n);
        $decrypted = $m->toBytes();
        while (strlen($decrypted) < $keyBytes) $decrypted = "\x00" . $decrypted;

        try {
            $expected = $this->pkcs1SignPad($data, $keyBytes, $hashAlgo);
            return hash_equals($expected, $decrypted);
        } catch (\RuntimeException) {
            return false;
        }
    }

    public function getPublicKey(): array {
        return ['n' => $this->n, 'e' => $this->e];
    }

    public function getPrivateKey(): array {
        return [
            'n' => $this->n, 'e' => $this->e, 'd' => $this->d,
            'p' => $this->p, 'q' => $this->q
        ];
    }
}
