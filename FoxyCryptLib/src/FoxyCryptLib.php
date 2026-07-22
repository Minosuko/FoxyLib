<?php
declare(strict_types=1);
namespace FoxyCryptLib;

use FoxyCryptLib\Certificate\{Extension, PKCS12, CABundle, CRL, OCSP};

class FoxyCryptLib {
    // Encoding
    public static function base64Encode(string $data, bool $urlSafe = false): string { return Base64::encode($data, $urlSafe); }
    public static function base64Decode(string $data, bool $urlSafe = false): string { return Base64::decode($data, $urlSafe); }
    public static function base32Encode(string $data, bool $hex = false): string { return Base32::encode($data, $hex); }
    public static function base32Decode(string $data, bool $hex = false): string { return Base32::decode($data, $hex); }

    // Random
    public static function randomBytes(int $length): string { return Random::bytes($length); }
    public static function randomInt(int $min, int $max): int { return Random::int($min, $max); }
    public static function randomFloat(float $min = 0.0, float $max = 1.0): float { return Random::float($min, $max); }
    public static function randomString(int $length, string $chars = ''): string { return Random::string($length, $chars); }

    // Hashing
    public static function hash(string $algo, string $data): string { return Hash::hash($algo, $data); }
    public static function hmac(string $algo, string $data, string $key): string { return Hash::hmac($algo, $data, $key); }
    public static function pbkdf2(string $algo, string $pass, string $salt, int $iterations, int $keyLen): string {
        return Hash::pbkdf2($algo, $pass, $salt, $iterations, $keyLen);
    }

    // AES
    public static function aesEncrypt(string $data, string $key, string $mode = 'CBC', string $iv = '', string $aad = ''): string|array {
        $aes = new Symmetric\AES($key);
        return $aes->encrypt($data, $mode, $iv, $aad);
    }
    public static function aesDecrypt(string $data, string $key, string $mode = 'CBC', string $iv = '', string $aad = '', string $tag = ''): string|array {
        $aes = new Symmetric\AES($key);
        return $aes->decrypt($data, $mode, $iv, $aad, $tag);
    }

    // RSA
    public static function rsaGenerateKeys(int $bits = 2048): RSA { return (new RSA($bits))->generateKeys(); }
    public static function rsaEncrypt(string $data, RSA $rsa): string { return $rsa->encrypt($data); }
    public static function rsaDecrypt(string $data, RSA $rsa): string { return $rsa->decrypt($data); }
    public static function rsaSign(string $data, RSA $rsa, string $hashAlgo = 'sha256'): string { return $rsa->sign($data, $hashAlgo); }
    public static function rsaVerify(string $data, string $signature, RSA $rsa, string $hashAlgo = 'sha256'): bool { return $rsa->verify($data, $signature, $hashAlgo); }

    // DSA
    public static function dsaGenerateKeys(int $bits = 2048): DSA { return (new DSA($bits))->generateKeys(); }
    public static function dsaSign(string $data, DSA $dsa): string { return $dsa->sign($data); }
    public static function dsaVerify(string $data, string $signature, DSA $dsa): bool { return $dsa->verify($data, $signature); }

    // PEM
    public static function pemEncode(string $der, string $label): string { return PEM::encode($der, $label); }
    public static function pemDecode(string $pem): array { return PEM::decode($pem); }

    // DER
    public static function derEncodeSequence(array $children): string { return DER::encodeSequence($children); }
    public static function derEncodeInteger(string $bytes): string { return DER::encodeInteger($bytes); }
    public static function derEncodeOID(string $oid): string { return DER::encodeOID($oid); }
    public static function derParse(string $data): array { return DER::parse($data); }

    // X.509 Certificates
    public static function createSelfSignedCertificate(RSA $key, array $subject, string $algo = 'sha256', int $days = 365): X509Certificate {
        return X509Certificate::createSelfSigned($key, $subject, $algo, $days);
    }
    public static function createSelfSignedCertificateEC(ECDSA $key, array $subject, string $algo = 'sha256', int $days = 365): X509Certificate {
        return X509Certificate::createSelfSignedEC($key, $subject, $algo, $days);
    }
    public static function createSignedCertificate(RSA $subjectKey, RSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365): X509Certificate {
        return X509Certificate::createSigned($subjectKey, $caKey, $subject, $issuer, $algo, $days);
    }
    public static function createSignedCertificateEC(ECDSA $subjectKey, ECDSA $caKey, array $subject, array $issuer, string $algo = 'sha256', int $days = 365): X509Certificate {
        return X509Certificate::createSignedEC($subjectKey, $caKey, $subject, $issuer, $algo, $days);
    }

    // X.509 Extensions
    public static function extension(string $oid, bool $critical, mixed $value): Extension { return new Extension($oid, $critical, $value); }
    public static function basicConstraints(bool $ca = false, ?int $pathLen = null): Extension { return Extension::makeBasicConstraints($ca, $pathLen); }
    public static function keyUsage(array $bits): Extension { return Extension::makeKeyUsage($bits); }
    public static function extendedKeyUsage(array $oids, bool $critical = false): Extension { return Extension::makeExtendedKeyUsage($oids, $critical); }
    public static function subjectKeyIdentifier(string $keyId): Extension { return Extension::makeSubjectKeyIdentifier($keyId); }
    public static function authorityKeyIdentifier(string $keyId): Extension { return Extension::makeAuthorityKeyIdentifier($keyId); }
    public static function subjectAltName(array $names): Extension { return Extension::makeSubjectAlternativeName($names); }
    public static function issuerAltName(array $names): Extension { return Extension::makeIssuerAlternativeName($names); }
    public static function crlDistributionPoint(string $url): array { return Extension::crlPoint($url); }
    public static function authorityInfoAccess(array $descs): Extension { return Extension::makeAuthorityInfoAccess($descs); }
    public static function certificatePolicies(array $policies): Extension { return Extension::makeCertificatePolicies($policies); }
    public static function nameConstraints(array $permitted = [], array $excluded = []): Extension { return Extension::makeNameConstraints($permitted, $excluded); }
    public static function policyConstraints(?int $requireExplicitPolicy = null, ?int $inhibitPolicyMapping = null): Extension { return Extension::makePolicyConstraints($requireExplicitPolicy, $inhibitPolicyMapping); }
    public static function tlsFeature(array $features): Extension { return Extension::makeTLSFeature($features); }
    public static function dnsName(string $dns): array { return Extension::dnsName($dns); }
    public static function ipAddress(string $ip): array { return Extension::ipAddress($ip); }
    public static function uri(string $uri): array { return Extension::uri($uri); }
    public static function rfc822Name(string $email): array { return Extension::rfc822Name($email); }
    public static function caIssuer(string $url): array { return Extension::caIssuer($url); }
    public static function ocspResponder(string $url): array { return Extension::ocspResponder($url); }

    // PKCS#12
    public static function pkcs12(string $password = ''): PKCS12 { return new PKCS12($password); }
    public static function pkcs12Decode(string $der, string $password): array { return PKCS12::decode($der, $password); }

    // CA Bundle
    public static function caBundle(): CABundle { return new CABundle(); }
    public static function buildChain(array $cert, CABundle $bundle): array { return CABundle::buildChain($cert, $bundle); }

    // CRL
    public static function createCRL(): CRL { return new CRL(); }
    public static function parseCRL(string $der): array { return CRL::fromDER($der); }
    public static function parseCRLFromPEM(string $pem): array { return CRL::fromPEM($pem); }

    // OCSP
    public static function ocspBuildRequest(string $issuerNameDer, string $issuerKeyHash, string $serialBytes, ?string $nonce = null): string {
        return OCSP::buildRequest($issuerNameDer, $issuerKeyHash, $serialBytes, $nonce);
    }
    public static function ocspParseRequest(string $der): array { return OCSP::parseRequest($der); }
    public static function ocspBuildResponse(array $responses, string $responderDer, string $signature, string $sigAlgoOid, ?array $certs = [], ?string $nonce = null): string {
        return OCSP::buildResponse($responses, $responderDer, $signature, $sigAlgoOid, $certs, $nonce);
    }
    public static function ocspParseResponse(string $der): array { return OCSP::parseResponse($der); }

    // ECDSA
    public static function ecdsaGenerateKeys(string $curve = 'P-256'): ECDSA { $e = new ECDSA($curve); $e->generateKeys(); return $e; }
}
