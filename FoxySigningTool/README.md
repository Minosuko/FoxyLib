# FoxySigningTool

## PFX signing

`signWithPFX()` loads the private key, selects the certificate whose public key matches it, and includes the remaining certificates as the chain.

```php
use FoxySigningTool\FoxySigningTool;

FoxySigningTool::signWithPFX('app.exe', 'codesign.pfx', 'password', [
    'output' => 'app-signed.exe',
    'hash' => 'sha256',
]);
```

PFX processing is implemented in PHP and does not call OpenSSL or another signing executable. The decoder supports SHA-1/SHA-2 PKCS#12 MACs and PBES2/PBKDF2 with AES-128-CBC or AES-256-CBC. `signWithPKCS12()` remains available as an equivalent API.

## APK signing

APK files are signed with Android signature schemes v1, v2, and v3. The implementation replaces existing APK signatures, adds stripping protection between schemes, and does not call `apksigner`, `jarsigner`, or OpenSSL.

```php
FoxySigningTool::signWithPFX('app.apk', 'android-signing.pfx', 'password', [
    'output' => 'app-signed.apk',
    'apkSignerName' => 'RELEASE',
    'apkMinSdk' => 24,
]);
```

APK signing currently supports RSA keys. Schemes v2/v3 use SHA-256; v1 uses SHA-256 for `apkMinSdk` 18 or newer and SHA-1 for older Android compatibility. Existing local ZIP records are preserved so signing does not disturb aligned native libraries.

Signing requires 64-bit PHP and the PHP zip extension. ZIP64 and multi-disk APKs are rejected. Single-signer v3 uses an open-ended maximum SDK (`2147483647`), `maxApkSize` defaults to 512 MiB, and RFC 3161 timestamps are not applicable to APK signatures.

## Timestamp signing

Set `timestampUrl` to request an RFC 3161 timestamp. Authenticode files use the Microsoft RFC 3161 unsigned-attribute OID; other CMS signatures use `id-aa-signatureTimeStampToken`.

```php
FoxySigningTool::signWithPFX('app.exe', 'codesign.pfx', 'password', [
    'output' => 'app-signed.exe',
    'timestampUrl' => 'https://timestamp.example.com',
    'timestampHash' => 'sha256',
    'timestampTimeout' => 15,
]);
```

Timestamping is supported for PE/EFI, MSI, ELF, Mach-O, PDF, and detached CMS signatures. OOXML and ODF use XML signatures and reject `timestampUrl` because those formats require XAdES-specific timestamp structures.
