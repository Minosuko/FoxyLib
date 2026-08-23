<?php
declare(strict_types=1);

require_once __DIR__ . '/../../FoxyCryptLib/autoload.php';

use FoxyCryptLib\RSA;
use FoxyCryptLib\X509Certificate;
use FoxyCryptLib\Certificate\Extension;

$foxyCabundle = __DIR__ . '/../bundle/foxycabundle.pem';
$privateStore = __DIR__ . '/../../FoxyCABundle';

if (!is_dir($privateStore)) {
    mkdir($privateStore, 0700, true);
}

echo "=== FoxySec CA Hierarchy Generator ===\n\n";

echo "Generating FoxySec Root CA...\n";
$rootKey = new RSA(4096);
$rootKey->generateKeys();
$rootSubject = ['CN' => 'FoxySec Root CA', 'O' => 'FoxyLib', 'C' => 'VN'];
$rootCert = X509Certificate::createSelfSigned($rootKey, $rootSubject, 'sha512', 150 * 365);
$rootSki = $rootCert->computeSubjectKeyIdentifier();
$rootCert->setExtensions([
    Extension::makeBasicConstraints(true, null),
    Extension::makeKeyUsage([0, 0, 0, 0, 0, 1, 1, 0]),
    Extension::makeSubjectKeyIdentifier($rootSki),
    Extension::makeAuthorityInfoAccess([
        Extension::caIssuer('http://foxysec.minofox.top/foxy/cabundle/root-ca.crt'),
        Extension::ocspResponder('http://foxysec.minofox.top/foxy/ocsp/root-ca'),
    ]),
]);
$rootPem = $rootCert->getPEM();
file_put_contents("$privateStore/root-ca.key", $rootKey->getPrivateKeyPEM());
file_put_contents("$privateStore/root-ca.crt", $rootPem);
echo "  Saved to FoxyCABundle/\n";

$hierarchy = [
    'TLS' => [
        'intermediate' => ['CN' => 'FoxySec Public F1 CA', 'OU' => 'TLS Sub-CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'issuing' => ['CN' => 'FoxySec TLS F1 2026 CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'eku' => [Extension::EKU_SERVER_AUTH, Extension::EKU_CLIENT_AUTH],
    ],
    'CodeSign' => [
        'intermediate' => ['CN' => 'FoxySec CodeSign F1 CA', 'OU' => 'CodeSign Sub-CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'issuing' => ['CN' => 'FoxySec CodeSign F1 2026 CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'eku' => [Extension::EKU_CODE_SIGNING],
    ],
    'ComCA' => [
        'intermediate' => ['CN' => 'FoxySec ComCA F1 CA', 'OU' => 'ComCA Sub-CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'issuing' => ['CN' => 'FoxySec ComCA F1 2026 CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'eku' => [Extension::EKU_SERVER_AUTH, Extension::EKU_CLIENT_AUTH, Extension::EKU_EMAIL_PROTECTION],
    ],
    'DocSign' => [
        'intermediate' => ['CN' => 'FoxySec DocSign F1 CA', 'OU' => 'DocSign Sub-CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'issuing' => ['CN' => 'FoxySec DocSign F1 2026 CA', 'O' => 'FoxySec', 'C' => 'VN'],
        'eku' => [Extension::EKU_DOCUMENT_SIGNING],
    ],
];

$foxyBundlePems = [$rootPem];
$typeShort = ['TLS' => 'tls', 'CodeSign' => 'codesign', 'ComCA' => 'comca', 'DocSign' => 'docsign'];

foreach ($hierarchy as $type => $info) {
    $prefix = $typeShort[$type];
    echo "\nGenerating $type hierarchy...\n";

    $intKey = new RSA(2048);
    $intKey->generateKeys();
    $intCert = X509Certificate::createSigned($intKey, $rootKey, $info['intermediate'], $rootSubject, 'sha256', 30 * 365);
    $intSki = $intCert->computeSubjectKeyIdentifier();
    $intCert->setExtensions([
        Extension::makeBasicConstraints(true, 0),
        Extension::makeKeyUsage([0, 0, 0, 0, 0, 1, 1, 0]),
        Extension::makeSubjectKeyIdentifier($intSki),
        Extension::makeAuthorityKeyIdentifier($rootSki),
        Extension::makeExtendedKeyUsage($info['eku'], false),
        Extension::makeAuthorityInfoAccess([
            Extension::caIssuer('http://foxysec.minofox.top/foxy/cabundle/root-ca.crt'),
            Extension::ocspResponder("http://foxysec.minofox.top/foxy/ocsp/$prefix-intermediate-ca"),
        ]),
    ]);
    $intPem = $intCert->getPEM();
    file_put_contents("$privateStore/$prefix-intermediate-ca.key", $intKey->getPrivateKeyPEM());
    file_put_contents("$privateStore/$prefix-intermediate-ca.crt", $intPem);
    echo "  Intermediate CA saved\n";
    $foxyBundlePems[] = $intPem;

    $issKey = new RSA(2048);
    $issKey->generateKeys();
    $issCert = X509Certificate::createSigned($issKey, $intKey, $info['issuing'], $info['intermediate'], 'sha256', 15 * 365);
    $issSki = $issCert->computeSubjectKeyIdentifier();
    $issCert->setExtensions([
        Extension::makeBasicConstraints(true, 0),
        Extension::makeKeyUsage([0, 0, 0, 0, 0, 1, 1, 0]),
        Extension::makeSubjectKeyIdentifier($issSki),
        Extension::makeAuthorityKeyIdentifier($intSki),
        Extension::makeExtendedKeyUsage($info['eku'], false),
        Extension::makeAuthorityInfoAccess([
            Extension::caIssuer("http://foxysec.minofox.top/foxy/cabundle/$prefix-intermediate-ca.crt"),
            Extension::ocspResponder("http://foxysec.minofox.top/foxy/ocsp/$prefix-issuing-ca"),
        ]),
    ]);
    $issPem = $issCert->getPEM();
    file_put_contents("$privateStore/$prefix-issuing-ca.key", $issKey->getPrivateKeyPEM());
    file_put_contents("$privateStore/$prefix-issuing-ca.crt", $issPem);
    echo "  Issuing CA saved\n";
    $foxyBundlePems[] = $issPem;
}

file_put_contents($foxyCabundle, implode("\n", $foxyBundlePems) . "\n");
echo "\n--- Done ---\n";
echo "Public CA certs:  bundle/foxycabundle.pem\n";
echo "Private keys+certs: FoxyCABundle/\n";
