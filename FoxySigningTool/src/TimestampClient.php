<?php
declare(strict_types=1);
namespace FoxySigningTool;

use FoxyCryptLib\{BigInt, DER, Hash};

final class TimestampClient {
    public const OID_TIMESTAMP_TOKEN = '1.2.840.113549.1.9.16.1.4';
    public const OID_SIGNATURE_TIMESTAMP = '1.2.840.113549.1.9.16.2.14';
    public const OID_AUTHENTICODE_TIMESTAMP = '1.3.6.1.4.1.311.3.3.1';

    public function __construct(
        private string $url,
        private int $timeout = 15
    ) {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('Timestamp URL must use HTTP or HTTPS');
        }
        if ($timeout < 1) {
            throw new \InvalidArgumentException('Timestamp timeout must be at least one second');
        }
    }

    public function timestamp(
        string $cms,
        string $hashAlgo = 'sha256',
        string $attributeOid = self::OID_SIGNATURE_TIMESTAMP
    ): string {
        $signature = $this->extractSignatureValue($cms);
        $nonce = random_bytes(8);
        $nonce[0] = chr((ord($nonce[0]) % 0x7f) + 1);
        $request = $this->buildRequest($signature, $hashAlgo, $nonce);
        $response = $this->send($request);
        $token = $this->parseResponse($response, $signature, $hashAlgo, $nonce);
        return $this->attachToken($cms, $token, $attributeOid);
    }

    public function buildRequest(string $signature, string $hashAlgo, string $nonce): string {
        $digest = hex2bin(Hash::hash($hashAlgo, $signature));
        return DER::encodeSequence([
            DER::encodeInteger("\x01"),
            DER::encodeSequence([
                DER::encodeSequence([
                    DER::encodeOID(PKCS7::hashAlgoToOid($hashAlgo)),
                    DER::encodeNull(),
                ]),
                DER::encodeOctetString($digest),
            ]),
            DER::encodeInteger($nonce),
            DER::encodeBoolean(true),
        ]);
    }

    public function parseResponse(
        string $response,
        string $signature,
        string $hashAlgo,
        string $nonce
    ): string {
        try {
            $parsed = DER::parse($response);
            $statusInfo = $parsed['children'][0] ?? null;
            $status = isset($statusInfo['children'][0]['data'])
                ? BigInt::fromBytes($statusInfo['children'][0]['data'])->toInt()
                : -1;
            if (!in_array($status, [0, 1], true)) {
                throw new \RuntimeException("Timestamp authority rejected the request (status {$status})");
            }
            $tokenNode = $parsed['children'][1] ?? null;
            if ($tokenNode === null || ($tokenNode['raw'] ?? '') === '') {
                throw new \RuntimeException('Timestamp response does not contain a token');
            }
            $token = $tokenNode['raw'];
            $this->validateToken($tokenNode, $signature, $hashAlgo, $nonce);
            return $token;
        } catch (\RuntimeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new \RuntimeException('Invalid timestamp response', 0, $exception);
        }
    }

    public function attachToken(
        string $cms,
        string $token,
        string $attributeOid = self::OID_SIGNATURE_TIMESTAMP
    ): string {
        $outer = DER::parse($cms);
        $signedData = $outer['children'][1]['children'][0] ?? null;
        if ($signedData === null || ($outer['children'][0]['oid'] ?? '') !== PKCS7::OID_SIGNED_DATA) {
            throw new \RuntimeException('Cannot timestamp invalid CMS SignedData');
        }
        $signedDataChildren = $signedData['children'];
        $signerInfosIndex = array_key_last($signedDataChildren);
        $signerInfos = $signedDataChildren[$signerInfosIndex]['children'] ?? [];
        if (count($signerInfos) !== 1) {
            throw new \RuntimeException('Timestamping requires exactly one CMS signer');
        }

        $signerChildren = $signerInfos[0]['children'];
        $attribute = DER::encodeSequence([
            DER::encodeOID($attributeOid),
            DER::encodeSet([$token]),
        ]);
        $last = array_key_last($signerChildren);
        if ($last !== null && $signerChildren[$last]['tag'] === 0xa1) {
            $attributes = $signerChildren[$last]['children'] ?? [];
            $attributes[] = ['raw' => $attribute];
            $attributeValues = array_column($attributes, 'raw');
            sort($attributeValues, SORT_STRING);
            $signerChildren[$last] = ['raw' => DER::encodeContextSpecific(
                1,
                implode('', $attributeValues),
                true
            )];
        } else {
            $signerChildren[] = ['raw' => DER::encodeContextSpecific(1, $attribute, true)];
        }

        $signedDataChildren[$signerInfosIndex] = ['raw' => DER::encodeSet([
            DER::encodeSequence(array_column($signerChildren, 'raw')),
        ])];
        $rebuiltSignedData = DER::encodeSequence(array_column($signedDataChildren, 'raw'));
        return DER::encodeSequence([
            $outer['children'][0]['raw'],
            DER::encodeContextSpecific(0, $rebuiltSignedData, true),
        ]);
    }

    private function send(string $request): string {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\n",
                'content' => $request,
                'timeout' => $this->timeout,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents($this->url, false, $context);
        $headers = $http_response_header ?? [];
        $statusLine = $headers[0] ?? '';
        if ($response === false || !preg_match('/^HTTP\/\S+\s+2\d\d\b/', $statusLine)) {
            throw new \RuntimeException("Timestamp request failed: {$statusLine}");
        }
        return $response;
    }

    private function extractSignatureValue(string $cms): string {
        $outer = DER::parse($cms);
        $signedData = $outer['children'][1]['children'][0] ?? null;
        $signerInfos = $signedData['children'][array_key_last($signedData['children'] ?? [])]['children'] ?? [];
        if (count($signerInfos) !== 1) {
            throw new \RuntimeException('Timestamping requires exactly one CMS signer');
        }
        $children = $signerInfos[0]['children'] ?? [];
        foreach (array_reverse($children) as $child) {
            if (($child['tag'] ?? null) === DER::TAG_OCTET_STRING) {
                return $child['data'];
            }
        }
        throw new \RuntimeException('CMS signer has no signature value');
    }

    private function validateToken(
        array $token,
        string $signature,
        string $hashAlgo,
        string $nonce
    ): void {
        if (($token['children'][0]['oid'] ?? '') !== PKCS7::OID_SIGNED_DATA) {
            throw new \RuntimeException('Timestamp token is not CMS SignedData');
        }
        $signedData = $token['children'][1]['children'][0] ?? null;
        $contentInfo = $signedData['children'][2] ?? null;
        if (($contentInfo['children'][0]['oid'] ?? '') !== self::OID_TIMESTAMP_TOKEN) {
            throw new \RuntimeException('Timestamp token has the wrong content type');
        }
        $tstOctets = $contentInfo['children'][1]['children'][0]['data'] ?? null;
        if (!is_string($tstOctets)) {
            throw new \RuntimeException('Timestamp token has no TSTInfo content');
        }
        $tstInfo = DER::parse($tstOctets);
        $imprint = $tstInfo['children'][2] ?? null;
        $actualOid = $imprint['children'][0]['children'][0]['oid'] ?? '';
        $actualDigest = $imprint['children'][1]['data'] ?? '';
        $expectedDigest = hex2bin(Hash::hash($hashAlgo, $signature));
        if ($actualOid !== PKCS7::hashAlgoToOid($hashAlgo)
            || !hash_equals($expectedDigest, $actualDigest)) {
            throw new \RuntimeException('Timestamp token message imprint does not match the signature');
        }
        $tokenNonce = null;
        foreach (array_slice($tstInfo['children'], 5) as $child) {
            if (($child['tag'] ?? null) === DER::TAG_INTEGER) {
                $tokenNonce = $child['data'];
                break;
            }
        }
        if ($tokenNonce === null || !hash_equals(ltrim($nonce, "\x00"), ltrim($tokenNonce, "\x00"))) {
            throw new \RuntimeException('Timestamp token nonce does not match the request');
        }
    }
}
