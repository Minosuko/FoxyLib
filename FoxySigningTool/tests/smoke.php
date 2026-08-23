<?php
declare(strict_types=1);

require dirname(__DIR__, 2) . '/FoxyCryptLib/autoload.php';
require dirname(__DIR__) . '/autoload.php';

use FoxyCryptLib\{DER, Hash};
use FoxySigningTool\{PKCS7, TimestampClient};

function expect(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$client = new TimestampClient('https://tsa.example.test');
$signature = 'synthetic-signature-value';
$nonce = "\x01\x23\x45\x67\x89\xab\xcd\xef";
$request = DER::parse($client->buildRequest($signature, 'sha256', $nonce));
expect(($request['children'][0]['data'] ?? '') === "\x01", 'Timestamp request version is invalid');
expect(
    ($request['children'][1]['children'][0]['children'][0]['oid'] ?? '') === PKCS7::OID_SHA256,
    'Timestamp request digest algorithm is invalid'
);

$digest = hex2bin(Hash::hash('sha256', $signature));
$tstInfo = DER::encodeSequence([
    DER::encodeInteger("\x01"),
    DER::encodeOID('1.2.3.4'),
    DER::encodeSequence([
        DER::encodeSequence([DER::encodeOID(PKCS7::OID_SHA256), DER::encodeNull()]),
        DER::encodeOctetString($digest),
    ]),
    DER::encodeInteger("\x01"),
    DER::encodeGeneralizedTime('20260815000000Z'),
    DER::encodeInteger($nonce),
]);
$timestampToken = DER::encodeSequence([
    DER::encodeOID(PKCS7::OID_SIGNED_DATA),
    DER::encodeContextSpecific(0, DER::encodeSequence([
        DER::encodeInteger("\x03"),
        DER::encodeSet([]),
        DER::encodeSequence([
            DER::encodeOID(TimestampClient::OID_TIMESTAMP_TOKEN),
            DER::encodeContextSpecific(0, DER::encodeOctetString($tstInfo), true),
        ]),
        DER::encodeSet([]),
    ]), true),
]);
$response = DER::encodeSequence([
    DER::encodeSequence([DER::encodeInteger("\x00")]),
    $timestampToken,
]);
expect(
    $client->parseResponse($response, $signature, 'sha256', $nonce) === $timestampToken,
    'Timestamp response token was not accepted'
);
$mismatchRejected = false;
try {
    $client->parseResponse($response, 'another-signature', 'sha256', $nonce);
} catch (RuntimeException) {
    $mismatchRejected = true;
}
expect($mismatchRejected, 'Timestamp response with a mismatched imprint was accepted');

$signerInfo = DER::encodeSequence([
    DER::encodeInteger("\x01"),
    DER::encodeSequence([]),
    DER::encodeSequence([DER::encodeOID(PKCS7::OID_SHA256), DER::encodeNull()]),
    DER::encodeSequence([DER::encodeOID(PKCS7::OID_RSA), DER::encodeNull()]),
    DER::encodeOctetString($signature),
]);
$cms = DER::encodeSequence([
    DER::encodeOID(PKCS7::OID_SIGNED_DATA),
    DER::encodeContextSpecific(0, DER::encodeSequence([
        DER::encodeInteger("\x01"),
        DER::encodeSet([]),
        DER::encodeSequence([DER::encodeOID(PKCS7::OID_DATA)]),
        DER::encodeSet([$signerInfo]),
    ]), true),
]);
$timestamped = DER::parse($client->attachToken($cms, $timestampToken));
$signedData = $timestamped['children'][1]['children'][0];
$signer = $signedData['children'][array_key_last($signedData['children'])]['children'][0];
$unsigned = $signer['children'][array_key_last($signer['children'])];
expect($unsigned['tag'] === 0xa1, 'CMS timestamp unsigned attributes are missing');
expect(
    ($unsigned['children'][0]['children'][0]['oid'] ?? '') === TimestampClient::OID_SIGNATURE_TIMESTAMP,
    'CMS timestamp attribute has the wrong OID'
);

echo "FoxySigningTool smoke tests passed\n";
