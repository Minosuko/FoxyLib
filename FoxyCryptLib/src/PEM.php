<?php
declare(strict_types=1);
namespace FoxyCryptLib;

class PEM {
    public static function encode(string $der, string $label, string $lineBreak = "\r\n"): string {
        $b64 = chunk_split(Base64::encode($der), 64, $lineBreak);
        return "-----BEGIN " . $label . "-----$lineBreak" . $b64 . "-----END " . $label . "-----$lineBreak";
    }

    public static function decode(string $pem): array {
        $result = ['label' => '', 'data' => '', 'headers' => []];
        $pem = str_replace(["\r\n", "\r"], "\n", $pem);
        $lines = explode("\n", $pem);
        $inData = false;
        $data = '';
        $label = '';
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;
            if (preg_match('/^-----BEGIN (.+?)-----/', $line, $m)) {
                $label = $m[1];
                $inData = true;
                $result['label'] = $label;
                continue;
            }
            if (preg_match('/^-----END/', $line)) {
                $inData = false;
                break;
            }
            if ($inData) {
                if (strpos($line, ':') !== false && !str_starts_with($line, '-----')) {
                    $parts = explode(':', $line, 2);
                    $result['headers'][trim($parts[0])] = trim($parts[1]);
                } else {
                    $data .= $line;
                }
            }
        }
        $result['data'] = Base64::decode($data);
        return $result;
    }

    public static function isPEM(string $data): bool {
        return str_contains($data, '-----BEGIN ');
    }

    public static function getKeyType(string $pem): string {
        $info = self::decode($pem);
        return $info['label'] ?? '';
    }

    public static function rsaPublicKeyToPEM(string $n, string $e): string {
        $der = DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID('1.2.840.113549.1.1.1'), // rsaEncryption
                DER::encodeNull()
            ]),
            DER::encodeBitString(DER::encodeSequence([
                DER::encodeInteger($n),
                DER::encodeInteger($e)
            ]))
        ]);
        return self::encode($der, 'PUBLIC KEY');
    }

    public static function rsaPrivateKeyToPEM(string $n, string $e, string $d, string $p, string $q, string $dp, string $dq, string $qi): string {
        $der = DER::encodeSequence([
            DER::encodeInteger("\x00"), // version
            DER::encodeInteger($n),
            DER::encodeInteger($e),
            DER::encodeInteger($d),
            DER::encodeInteger($p),
            DER::encodeInteger($q),
            DER::encodeInteger($dp),
            DER::encodeInteger($dq),
            DER::encodeInteger($qi)
        ]);
        return self::encode($der, 'RSA PRIVATE KEY');
    }

    public static function pemToRSAPublicKey(string $pem): array {
        $info = self::decode($pem);
        $der = $info['data'];
        $parsed = DER::parse($der);
        $seq = $parsed['children'][0]['children'];
        $bitString = $parsed['children'][1]['data'];
        // BIT STRING has an unused-bits byte prefix - skip it
        $bitContent = substr($bitString, 1);
        $keySeq = DER::parse($bitContent);
        $n = $keySeq['children'][0]['data'];
        $e = $keySeq['children'][1]['data'];
        return ['n' => BigInt::fromBytes($n), 'e' => BigInt::fromBytes($e)];
    }

    public static function pemToRSAPrivateKey(string $pem): array {
        $info = self::decode($pem);
        $der = $info['data'];
        $parsed = DER::parse($der);
        $seq = $parsed['children'];
        return [
            'n' => BigInt::fromBytes($seq[1]['data']),
            'e' => BigInt::fromBytes($seq[2]['data']),
            'd' => BigInt::fromBytes($seq[3]['data']),
            'p' => BigInt::fromBytes($seq[4]['data']),
            'q' => BigInt::fromBytes($seq[5]['data']),
            'dp' => BigInt::fromBytes($seq[6]['data']),
            'dq' => BigInt::fromBytes($seq[7]['data']),
            'qi' => BigInt::fromBytes($seq[8]['data'])
        ];
    }

    public static function dsaPublicKeyToPEM(string $p, string $q, string $g, string $y): string {
        $der = DER::encodeSequence([
            DER::encodeSequence([
                DER::encodeOID('1.2.840.10040.4.1'), // id-dsa
                DER::encodeSequence([
                    DER::encodeInteger($p),
                    DER::encodeInteger($q),
                    DER::encodeInteger($g)
                ])
            ]),
            DER::encodeBitString(DER::encodeInteger($y))
        ]);
        return self::encode($der, 'PUBLIC KEY');
    }

    public static function dsaPrivateKeyToPEM(string $p, string $q, string $g, string $y, string $x): string {
        $der = DER::encodeSequence([
            DER::encodeInteger("\x00"),
            DER::encodeSequence([
                DER::encodeOID('1.2.840.10040.4.1'),
                DER::encodeSequence([
                    DER::encodeInteger($p),
                    DER::encodeInteger($q),
                    DER::encodeInteger($g)
                ])
            ]),
            DER::encodeOctetString(DER::encodeInteger($x))
        ]);
        return self::encode($der, 'DSA PRIVATE KEY');
    }

    public static function pemToDSAPublicKey(string $pem): array {
        $info = self::decode($pem);
        $parsed = DER::parse($info['data']);
        $algSeq = $parsed['children'][0]['children'][1]['children'];
        $bitString = $parsed['children'][1]['data'];
        $bitContent = substr($bitString, 1);
        $y = DER::parse($bitContent);
        return [
            'p' => BigInt::fromBytes($algSeq[0]['data']),
            'q' => BigInt::fromBytes($algSeq[1]['data']),
            'g' => BigInt::fromBytes($algSeq[2]['data']),
            'y' => BigInt::fromBytes($y['children'][0]['data'])
        ];
    }

    public static function pemToDSAPrivateKey(string $pem): array {
        $info = self::decode($pem);
        $parsed = DER::parse($info['data']);
        $seq = $parsed['children'];
        $algSeq = $seq[1]['children'][1]['children'];
        $x = DER::parse($seq[2]['data']);
        return [
            'p' => BigInt::fromBytes($algSeq[0]['data']),
            'q' => BigInt::fromBytes($algSeq[1]['data']),
            'g' => BigInt::fromBytes($algSeq[2]['data']),
            'y' => BigInt::fromBytes($seq[1]['children'][0]['data'] ?? ''),
            'x' => BigInt::fromBytes($x['children'][0]['data'])
        ];
    }
}
