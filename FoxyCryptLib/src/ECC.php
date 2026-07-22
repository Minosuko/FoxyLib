<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class ECC {
    public BigInt $p;
    public BigInt $a;
    public BigInt $b;
    public BigInt $gx;
    public BigInt $gy;
    public BigInt $n;
    public int $h;
    public string $name;
    public string $oid;
    public int $keySize;
    public string $hashAlgo;

    private const CURVES = [
        'P-192' => [
            'p' => 'fffffffffffffffffffffffffffffffeffffffffffffffff',
            'a' => 'fffffffffffffffffffffffffffffffefffffffffffffffc',
            'b' => '64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
            'gx' => '188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',
            'gy' => '07192b95ffc8da78631011ed6b24cdd573f977a11e794811',
            'n' => 'ffffffffffffffffffffffff99def836146bc9b1b4d22831',
            'h' => 1, 'size' => 192, 'hash' => 'sha256',
            'oid' => '1.2.840.10045.3.1.1',
        ],
        'P-256' => [
            'p' => 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
            'a' => 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
            'b' => '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
            'gx' => '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
            'gy' => '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
            'n' => 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
            'h' => 1, 'size' => 256, 'hash' => 'sha256',
            'oid' => '1.2.840.10045.3.1.7',
        ],
        'P-384' => [
            'p' => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
            'a' => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
            'b' => 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
            'gx' => 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
            'gy' => '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
            'n' => 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
            'h' => 1, 'size' => 384, 'hash' => 'sha384',
            'oid' => '1.3.132.0.34',
        ],
        'P-521' => [
            'p' => '000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            'a' => '000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc',
            'b' => '00000051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
            'gx' => '000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
            'gy' => '0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
            'n' => '000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
            'h' => 1, 'size' => 521, 'hash' => 'sha512',
            'oid' => '1.3.132.0.35',
        ],
        'secp256k1' => [
            'p' => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
            'a' => '0000000000000000000000000000000000000000000000000000000000000000',
            'b' => '0000000000000000000000000000000000000000000000000000000000000007',
            'gx' => '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            'gy' => '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            'n' => 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
            'h' => 1, 'size' => 256, 'hash' => 'sha256',
            'oid' => '1.3.132.0.10',
        ],
    ];

    public function __construct(string $curveName = 'P-256') {
        $c = self::CURVES[$curveName] ?? throw new \InvalidArgumentException("Unknown curve: $curveName");
        $this->p = BigInt::fromHex($c['p']);
        $this->a = BigInt::fromHex($c['a']);
        $this->b = BigInt::fromHex($c['b']);
        $this->gx = BigInt::fromHex($c['gx']);
        $this->gy = BigInt::fromHex($c['gy']);
        $this->n = BigInt::fromHex($c['n']);
        $this->h = $c['h'];
        $this->name = $curveName;
        $this->oid = $c['oid'];
        $this->keySize = $c['size'];
        $this->hashAlgo = $c['hash'];
    }

    public static function fromOID(string $oid): self {
        foreach (self::CURVES as $name => $c) {
            if ($c['oid'] === $oid) return new self($name);
        }
        throw new \InvalidArgumentException("Unknown curve OID: $oid");
    }

    public static function getCurveNames(): array {
        return array_keys(self::CURVES);
    }

    public static function isInfinity(?BigInt $x, ?BigInt $y): bool {
        return $x === null || $y === null;
    }

    public static function pointNegate(?BigInt $x, ?BigInt $y, BigInt $p): array {
        if (self::isInfinity($x, $y)) return [null, null];
        return [$x, $p->sub($y)];
    }

    public static function pointAdd(?BigInt $x1, ?BigInt $y1, ?BigInt $x2, ?BigInt $y2, BigInt $p, BigInt $a): array {
        if (self::isInfinity($x1, $y1)) return [$x2, $y2];
        if (self::isInfinity($x2, $y2)) return [$x1, $y1];
        if ($x1->equals($x2)) {
            if (!$y1->equals($y2)) return [null, null];
            if ($y1->isZero()) return [null, null];
            return self::pointDouble($x1, $y1, $p, $a);
        }
        $inv = Accel::modInverse($x2->sub($x1), $p);
        $slope = Accel::mod(Accel::multiply($y2->sub($y1), $inv), $p);
        $x3 = Accel::mod(Accel::multiply($slope, $slope)->sub($x1)->sub($x2), $p);
        $y3 = Accel::mod(Accel::multiply($slope, $x1->sub($x3))->sub($y1), $p);
        return [$x3, $y3];
    }

    public static function pointDouble(?BigInt $x, ?BigInt $y, BigInt $p, BigInt $a): array {
        if (self::isInfinity($x, $y) || $y->isZero()) return [null, null];
        $num = $x->multiply($x)->mulInt(3)->add($a);
        $den = $y->mulInt(2);
        $denInv = Accel::modInverse($den, $p);
        $slope = Accel::mod(Accel::multiply($num, $denInv), $p);
        $x3 = Accel::mod(Accel::multiply($slope, $slope)->sub($x->mulInt(2)), $p);
        $y3 = Accel::mod(Accel::multiply($slope, $x->sub($x3))->sub($y), $p);
        return [$x3, $y3];
    }

    public static function pointMultiply(BigInt $k, ?BigInt $x, ?BigInt $y, BigInt $p, BigInt $a): array {
        if (self::isInfinity($x, $y) || $k->isZero()) return [null, null];
        $rx = null; $ry = null;
        $kx = $x; $ky = $y;
        $bits = $k->bitLength();
        for ($i = 0; $i < $bits; $i++) {
            if (!BigInt::fromInt(1)->shiftLeft($i)->and($k)->isZero()) {
                [$rx, $ry] = self::pointAdd($rx, $ry, $kx, $ky, $p, $a);
            }
            [$kx, $ky] = self::pointDouble($kx, $ky, $p, $a);
        }
        return [$rx, $ry];
    }

    public function generateKeyPair(): array {
        $d = BigInt::randomRange(BigInt::fromInt(1), $this->n->sub(BigInt::fromInt(1)));
        [$qx, $qy] = self::pointMultiply($d, $this->gx, $this->gy, $this->p, $this->a);
        return ['d' => $d, 'x' => $qx, 'y' => $qy];
    }

    public static function encodePoint(BigInt $x, BigInt $y, int $keySize): string {
        $size = intdiv($keySize + 7, 8);
        $xb = $x->toBytes();
        $yb = $y->toBytes();
        $xb = str_pad($xb, $size, "\x00", STR_PAD_LEFT);
        $yb = str_pad($yb, $size, "\x00", STR_PAD_LEFT);
        return "\x04" . $xb . $yb;
    }

    public static function decodePoint(string $data, int $keySize): array {
        $size = intdiv($keySize + 7, 8);
        $fmt = ord($data[0]);
        if ($fmt === 0x04) {
            $xb = substr($data, 1, $size);
            $yb = substr($data, 1 + $size, $size);
            return [BigInt::fromBytes($xb), BigInt::fromBytes($yb)];
        }
        throw new \RuntimeException("Unsupported point format: $fmt");
    }

    public function getPublicKeyPEM(BigInt $x, BigInt $y): string {
        $point = self::encodePoint($x, $y, $this->keySize);
        $der = DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID('1.2.840.10045.2.1'),
                DER::encodeOID($this->oid)
            ]),
            DER::encodeBitString($point)
        ]);
        return PEM::encode($der, 'PUBLIC KEY');
    }

    public function getPrivateKeyPEM(BigInt $d, ?BigInt $x = null, ?BigInt $y = null): string {
        $size = intdiv($this->keySize + 7, 8);
        $pkBytes = str_pad($d->toBytes(), $size, "\x00", STR_PAD_LEFT);
        $parts = [
            DER::encodeInteger("\x01"),
            DER::encodeOctetString($pkBytes),
        ];
        if ($x !== null && $y !== null) {
            $parts[] = DER::encodeContextSpecific(0, DER::encodeOID($this->oid));
            $point = self::encodePoint($x, $y, $this->keySize);
            $parts[] = DER::encodeContextSpecific(1, DER::encodeBitString($point));
        }
        return PEM::encode(DER::encodeSequence($parts), 'EC PRIVATE KEY');
    }

    public static function pemToPublicKey(string $pem): array {
        $info = PEM::decode($pem);
        $parsed = DER::parse($info['data']);
        $algId = $parsed['children'][0];
        $curveOID = $algId['children'][1]['oid'] ?? '';
        $bitString = $parsed['children'][1]['data'];
        $pointData = substr($bitString, 1);
        $curve = self::fromOID($curveOID);
        [$x, $y] = self::decodePoint($pointData, $curve->keySize);
        return ['curve' => $curve, 'x' => $x, 'y' => $y, 'oid' => $curveOID];
    }

    public static function pemToPrivateKey(string $pem): array {
        $info = PEM::decode($pem);
        $parsed = DER::parse($info['data']);
        $pkBytes = $parsed['children'][1]['data'];
        $curve = null;
        $x = null; $y = null;
        foreach ($parsed['children'] as $child) {
            $tag = $child['tag'];
            if ($tag === 0xa0) {
                $inner = $child['children'][0] ?? [];
                $curve = self::fromOID($inner['oid'] ?? '');
            } elseif ($tag === 0xa1) {
                $bitString = $child['children'][0]['data'] ?? '';
                $pointData = substr($bitString, 1);
                if ($curve) [$x, $y] = self::decodePoint($pointData, $curve->keySize);
            }
        }
        if (!$curve) throw new \RuntimeException('Curve OID not found in private key');
        $d = BigInt::fromBytes($pkBytes);
        return ['curve' => $curve, 'd' => $d, 'x' => $x, 'y' => $y];
    }
}
