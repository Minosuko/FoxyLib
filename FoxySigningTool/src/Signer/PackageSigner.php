<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use FoxyCryptLib\Hash;
use FoxyCryptLib\PEM;
use FoxyCryptLib\RSA;
use FoxyCryptLib\X509Certificate;
use ZipArchive;

final class PackageSigner {
    private const DEFAULT_MAX_ZIP_ENTRIES = 20000;
    private const DEFAULT_MAX_ZIP_ENTRY_SIZE = 536870912;
    private const DEFAULT_MAX_ZIP_TOTAL_SIZE = 2147483648;
    private const DEFAULT_MAX_ZIP_RATIO = 1000;

    private const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
    private const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    private const CONTENT_TYPES_NS = 'http://schemas.openxmlformats.org/package/2006/content-types';
    private const RELATIONSHIPS_NS = 'http://schemas.openxmlformats.org/package/2006/relationships';
    private const OPC_SIGNATURE_NS = 'http://schemas.openxmlformats.org/package/2006/digital-signature';
    private const OPC_RELATIONSHIP_TRANSFORM = 'http://schemas.openxmlformats.org/package/2006/RelationshipTransform';
    private const OPC_ORIGIN_RELATIONSHIP = 'http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin';
    private const OPC_SIGNATURE_RELATIONSHIP = 'http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature';
    private const OPC_ORIGIN_CONTENT_TYPE = 'application/vnd.openxmlformats-package.digital-signature-origin';
    private const OPC_SIGNATURE_CONTENT_TYPE = 'application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml';
    private const OPC_RELATIONSHIPS_CONTENT_TYPE = 'application/vnd.openxmlformats-package.relationships+xml';

    private const ODF_SIGNATURE_NS = 'urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0';
    private const ODF_MANIFEST_NS = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';
    private const ODF_SIGNATURE_PATH = 'META-INF/documentsignatures.xml';

    private RSA $signerKey;
    private string $certDer;
    private array $extraCertsDer = [];

    public function __construct(object $signerKey, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('Package signing requires an RSA private key');
        }
        if (strtolower($hashAlgo) !== 'sha256') {
            throw new \InvalidArgumentException('Package signing currently supports SHA-256 only');
        }

        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY'));
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('Package signing requires an RSA certificate', 0, $exception);
        }
        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('Package signing key does not match the certificate');
        }

        $this->signerKey = $signerKey;
        $this->certDer = PEM::decode($certPem)['data'];
        foreach ($extraCerts as $extraCert) {
            if (!is_string($extraCert)) {
                throw new \InvalidArgumentException('Each extra certificate must be PEM encoded');
            }
            X509Certificate::fromPEM($extraCert);
            $this->extraCertsDer[] = PEM::decode($extraCert)['data'];
        }
    }

    public function signFile(
        string $inputPath,
        ?string $outputPath = null,
        ?string $format = null,
        array $options = []
    ): string {
        $package = @file_get_contents($inputPath);
        if ($package === false) {
            throw new \RuntimeException("Unable to read document package: {$inputPath}");
        }

        $signed = $this->signBinary($package, $format, $options);
        $outputPath ??= $inputPath;
        $this->writeFileSafely($outputPath, $signed);

        return $outputPath;
    }

    private function writeFileSafely(string $path, string $contents): void {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            throw new \RuntimeException("Output directory does not exist: {$directory}");
        }
        $temporary = tempnam($directory, '.foxy-sign-');
        if ($temporary === false) {
            throw new \RuntimeException("Unable to create temporary output beside: {$path}");
        }

        try {
            $written = @file_put_contents($temporary, $contents, LOCK_EX);
            if ($written !== strlen($contents)) {
                throw new \RuntimeException("Unable to write the complete signed document: {$path}");
            }
            if (@rename($temporary, $path)) {
                $temporary = '';
                return;
            }

            $backup = tempnam($directory, '.foxy-backup-');
            if ($backup === false || !@unlink($backup) || !@rename($path, $backup)) {
                throw new \RuntimeException("Unable to replace signed document: {$path}");
            }
            try {
                if (!@rename($temporary, $path)) {
                    @rename($backup, $path);
                    throw new \RuntimeException("Unable to replace signed document: {$path}");
                }
                $temporary = '';
                @unlink($backup);
            } catch (\Throwable $exception) {
                if (!file_exists($path)) {
                    @rename($backup, $path);
                }
                throw $exception;
            }
        } finally {
            if ($temporary !== '') {
                @unlink($temporary);
            }
        }
    }

    public function signBinary(string $package, ?string $format = null, array $options = []): string {
        if (str_starts_with($package, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
            throw new \RuntimeException('Legacy binary Office formats are not supported; convert the file to OOXML first');
        }
        if (!str_starts_with($package, "PK\x03\x04") && !str_starts_with($package, "PK\x05\x06")) {
            throw new \RuntimeException('Document is not an OOXML or OpenDocument ZIP package');
        }

        $tempPath = tempnam(sys_get_temp_dir(), 'foxy-document-');
        if ($tempPath === false) {
            throw new \RuntimeException('Unable to create a temporary package');
        }
        if (@file_put_contents($tempPath, $package) === false) {
            @unlink($tempPath);
            throw new \RuntimeException('Unable to initialize a temporary package');
        }

        $zip = new ZipArchive();
        $opened = false;
        try {
            $result = $zip->open($tempPath, ZipArchive::CHECKCONS);
            if ($result !== true) {
                throw new \RuntimeException("Unable to open document ZIP package (ZipArchive error {$result})");
            }
            $opened = true;
            $entries = $this->readEntries($zip, $options);
            $format = $this->detectFormat($entries, $format);

            $updates = match ($format) {
                'ooxml' => $this->signOOXML($entries, $options),
                'odf' => $this->signODF($entries, $options),
                default => throw new \RuntimeException("Unsupported document package format: {$format}"),
            };

            foreach ($updates as $name => $contents) {
                if (!$zip->addFromString($name, $contents)) {
                    throw new \RuntimeException("Unable to write ZIP entry: {$name}");
                }
                $zip->setCompressionName($name, ZipArchive::CM_DEFLATE);
            }
            if ($format === 'odf') {
                $zip->setCompressionName('mimetype', ZipArchive::CM_STORE);
            }

            if (!$zip->close()) {
                throw new \RuntimeException('Unable to finalize signed document package');
            }
            $opened = false;

            $signed = @file_get_contents($tempPath);
            if ($signed === false) {
                throw new \RuntimeException('Unable to read finalized document package');
            }
            if ($format === 'odf') {
                $this->validateODFMimetypeEntry($signed);
            }
            return $signed;
        } finally {
            if ($opened) {
                $zip->close();
            }
            @unlink($tempPath);
        }
    }

    private function readEntries(ZipArchive $zip, array $options): array {
        $maxEntries = $this->integerOption(
            $options,
            'maxZipEntries',
            self::DEFAULT_MAX_ZIP_ENTRIES
        );
        $maxEntrySize = $this->integerOption(
            $options,
            'maxZipEntrySize',
            self::DEFAULT_MAX_ZIP_ENTRY_SIZE
        );
        $maxTotalSize = $this->integerOption(
            $options,
            'maxZipTotalSize',
            self::DEFAULT_MAX_ZIP_TOTAL_SIZE
        );
        $maxRatio = $this->integerOption(
            $options,
            'maxZipCompressionRatio',
            self::DEFAULT_MAX_ZIP_RATIO
        );
        if ($zip->numFiles > $maxEntries) {
            throw new \RuntimeException("ZIP package has too many entries ({$zip->numFiles})");
        }

        $stats = [];
        $totalSize = 0;
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $stat = $zip->statIndex($index);
            if ($stat === false || !isset($stat['name'], $stat['size'], $stat['comp_size'])) {
                throw new \RuntimeException("Unable to inspect ZIP entry {$index}");
            }
            $size = (int)$stat['size'];
            $compressedSize = (int)$stat['comp_size'];
            if ($size < 0 || $compressedSize < 0 || $size > $maxEntrySize) {
                throw new \RuntimeException("ZIP entry exceeds the permitted size: {$stat['name']}");
            }
            if ($totalSize > $maxTotalSize - $size) {
                throw new \RuntimeException('ZIP package exceeds the permitted uncompressed size');
            }
            $totalSize += $size;

            $method = (int)($stat['comp_method'] ?? ZipArchive::CM_STORE);
            if (!in_array($method, [ZipArchive::CM_STORE, ZipArchive::CM_DEFLATE], true)) {
                throw new \RuntimeException("Unsupported ZIP compression method for: {$stat['name']}");
            }
            $encryption = (int)($stat['encryption_method'] ?? ZipArchive::EM_NONE);
            if ($encryption !== ZipArchive::EM_NONE) {
                throw new \RuntimeException("Encrypted ZIP entries are not supported: {$stat['name']}");
            }
            if ($size >= 1048576
                && ($compressedSize === 0 || ($size / $compressedSize) > $maxRatio)) {
                throw new \RuntimeException("ZIP entry has an unsafe compression ratio: {$stat['name']}");
            }
            $stats[] = $stat;
        }

        $entries = [];
        foreach ($stats as $index => $stat) {
            $name = str_replace('\\', '/', $stat['name']);
            $segments = explode('/', rtrim($name, '/'));
            if ($name === '' || str_starts_with($name, '/') || in_array('..', $segments, true)) {
                throw new \RuntimeException("Unsafe ZIP entry path: {$name}");
            }
            if (str_ends_with($name, '/')) {
                continue;
            }
            if (array_key_exists($name, $entries)) {
                throw new \RuntimeException("Duplicate ZIP entry: {$name}");
            }

            $contents = $zip->getFromIndex($index);
            if ($contents === false) {
                throw new \RuntimeException("Unable to read ZIP entry, possibly because it is encrypted: {$name}");
            }
            $entries[$name] = $contents;
        }
        return $entries;
    }

    private function integerOption(array $options, string $name, int $default): int {
        if (!array_key_exists($name, $options)) {
            return $default;
        }
        if (!is_int($options[$name]) || $options[$name] < 1) {
            throw new \InvalidArgumentException("{$name} must be a positive integer");
        }
        return $options[$name];
    }

    private function stringOption(array $options, string $name, string $default): string {
        if (!array_key_exists($name, $options)) {
            return $default;
        }
        if (!is_string($options[$name])) {
            throw new \InvalidArgumentException("{$name} must be a string");
        }
        return $options[$name];
    }

    private function opcSigningTime(mixed $value): string {
        if ($value === null) {
            return date(DATE_ATOM);
        }
        if ($value instanceof \DateTimeInterface) {
            return $value->format('Y-m-d\\TH:i:sP');
        }
        if (!is_string($value)
            || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/D', $value) !== 1) {
            throw new \InvalidArgumentException('signingTime must be an ISO 8601 timestamp with seconds');
        }
        try {
            new \DateTimeImmutable($value);
        } catch (\Exception $exception) {
            throw new \InvalidArgumentException('signingTime is not a valid timestamp', 0, $exception);
        }
        return $value;
    }

    private function detectFormat(array $entries, ?string $requested): string {
        if ($requested !== null) {
            $requested = strtolower($requested);
            if (!in_array($requested, ['ooxml', 'odf'], true)) {
                throw new \InvalidArgumentException("Unknown document package format: {$requested}");
            }
        }

        $isOOXML = isset($entries['[Content_Types].xml'], $entries['_rels/.rels'])
            && (isset($entries['word/document.xml'])
                || isset($entries['xl/workbook.xml'])
                || isset($entries['ppt/presentation.xml']));
        $isODF = isset($entries['mimetype'], $entries['META-INF/manifest.xml'])
            && $this->isODFMimetype($entries['mimetype']);

        $detected = $isOOXML ? 'ooxml' : ($isODF ? 'odf' : null);
        if ($detected === null) {
            throw new \RuntimeException('ZIP package is neither a supported OOXML nor OpenDocument file');
        }
        if ($requested !== null && $requested !== $detected) {
            throw new \RuntimeException("Document contents are {$detected}, not {$requested}");
        }
        return $detected;
    }

    private function signOOXML(array $entries, array $options): array {
        $this->validateOPCPartNames(array_keys($entries));
        $contentTypes = $this->loadXML($entries['[Content_Types].xml'], '[Content_Types].xml');
        if ($contentTypes->documentElement?->localName !== 'Types'
            || $contentTypes->documentElement->namespaceURI !== self::CONTENT_TYPES_NS) {
            throw new \RuntimeException('OOXML package has an invalid content-types namespace');
        }

        $rootRelationships = $this->loadRelationships($entries['_rels/.rels'], '_rels/.rels');
        $originRelationship = $this->findRelationshipByType($rootRelationships, self::OPC_ORIGIN_RELATIONSHIP);
        if ($originRelationship === null) {
            $originName = '_xmlsignatures/origin.sigs';
            $relationshipId = $this->nextRelationshipId($rootRelationships, 'rIdFoxySignatureOrigin');
            $originRelationship = $rootRelationships->createElementNS(self::RELATIONSHIPS_NS, 'Relationship');
            $originRelationship->setAttribute('Id', $relationshipId);
            $originRelationship->setAttribute('Type', self::OPC_ORIGIN_RELATIONSHIP);
            $originRelationship->setAttribute('Target', $originName);
            $rootRelationships->documentElement->appendChild($originRelationship);
        } else {
            if (strcasecmp($originRelationship->getAttribute('TargetMode'), 'External') === 0) {
                throw new \RuntimeException('OOXML signature origin cannot be external');
            }
            $originName = $this->resolveRelationshipTarget('', $originRelationship->getAttribute('Target'));
        }

        $originDirectory = dirname($originName);
        if ($originDirectory === '.') {
            $originDirectory = '';
        }
        $originRelationshipsName = ($originDirectory === '' ? '' : $originDirectory . '/')
            . '_rels/' . basename($originName) . '.rels';

        if (isset($entries[$originRelationshipsName])) {
            $originRelationships = $this->loadRelationships(
                $entries[$originRelationshipsName],
                $originRelationshipsName
            );
        } else {
            $originRelationships = $this->newRelationshipsDocument();
        }

        $signatureNumber = 1;
        $signaturePattern = '/^' . preg_quote($originDirectory === '' ? '' : $originDirectory . '/', '/')
            . 'sig(\d+)\.xml$/i';
        foreach (array_keys($entries) as $name) {
            if (preg_match($signaturePattern, $name, $match)) {
                $signatureNumber = max($signatureNumber, (int)$match[1] + 1);
            }
        }
        $signatureName = ($originDirectory === '' ? '' : $originDirectory . '/') . "sig{$signatureNumber}.xml";

        $signatureRelationship = $originRelationships->createElementNS(self::RELATIONSHIPS_NS, 'Relationship');
        $signatureRelationshipId = $this->nextRelationshipId(
            $originRelationships,
            "rIdSignature{$signatureNumber}"
        );
        $signatureRelationship->setAttribute('Id', $signatureRelationshipId);
        $signatureRelationship->setAttribute('Type', self::OPC_SIGNATURE_RELATIONSHIP);
        $signatureRelationship->setAttribute('Target', basename($signatureName));
        $originRelationships->documentElement->appendChild($signatureRelationship);

        $this->ensureContentType(
            $contentTypes,
            '/' . $originName,
            pathinfo($originName, PATHINFO_EXTENSION),
            self::OPC_ORIGIN_CONTENT_TYPE
        );
        $this->ensureContentType(
            $contentTypes,
            '/' . $signatureName,
            null,
            self::OPC_SIGNATURE_CONTENT_TYPE
        );

        $entries['[Content_Types].xml'] = $this->saveXML($contentTypes);
        $entries['_rels/.rels'] = $this->saveXML($rootRelationships);
        $entries[$originName] ??= '';
        $entries[$originRelationshipsName] = $this->saveXML($originRelationships);

        $contentTypeMap = $this->resolveContentTypes($entries, $this->contentTypeMap($contentTypes));
        $signatureId = $this->stringOption(
            $options,
            'signatureId',
            "idPackageSignature{$signatureNumber}"
        );
        $entries[$signatureName] = $this->buildOPCSignature(
            $entries,
            $contentTypeMap,
            $signatureName,
            $originRelationshipsName,
            $signatureRelationshipId,
            $signatureId,
            $options
        );

        return [
            '[Content_Types].xml' => $entries['[Content_Types].xml'],
            '_rels/.rels' => $entries['_rels/.rels'],
            $originName => $entries[$originName],
            $originRelationshipsName => $entries[$originRelationshipsName],
            $signatureName => $entries[$signatureName],
        ];
    }

    private function buildOPCSignature(
        array $entries,
        array $contentTypes,
        string $signatureName,
        string $originRelationshipsName,
        string $signatureRelationshipId,
        string $signatureId,
        array $options
    ): string {
        $this->validateXMLId($signatureId, 'OOXML signatureId');
        if (in_array($signatureId, ['idPackageObject', 'idSignatureTime'], true)) {
            throw new \InvalidArgumentException("OOXML signatureId is reserved: {$signatureId}");
        }
        $countersignExisting = $options['countersignExisting'] ?? false;
        if (!is_bool($countersignExisting)) {
            throw new \InvalidArgumentException('countersignExisting must be a boolean');
        }
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;

        $signature = $document->createElementNS(self::XMLDSIG_NS, 'Signature');
        $signature->setAttribute('Id', $signatureId);
        $signature->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:mdssi',
            self::OPC_SIGNATURE_NS
        );
        $document->appendChild($signature);

        $signedInfo = $this->dsElement($document, 'SignedInfo', $signature);
        $canonicalization = $this->dsElement($document, 'CanonicalizationMethod', $signedInfo);
        $canonicalization->setAttribute('Algorithm', self::C14N);
        $signatureMethod = $this->dsElement($document, 'SignatureMethod', $signedInfo);
        $signatureMethod->setAttribute('Algorithm', self::RSA_SHA256);

        $packageReference = $this->dsElement($document, 'Reference', $signedInfo);
        $packageReference->setAttribute('URI', '#idPackageObject');
        $packageReference->setAttribute('Type', self::XMLDSIG_NS . 'Object');
        $transforms = $this->dsElement($document, 'Transforms', $packageReference);
        $transform = $this->dsElement($document, 'Transform', $transforms);
        $transform->setAttribute('Algorithm', self::C14N);
        $digestMethod = $this->dsElement($document, 'DigestMethod', $packageReference);
        $digestMethod->setAttribute('Algorithm', self::SHA256);
        $packageDigestValue = $this->dsElement($document, 'DigestValue', $packageReference);

        $signatureValue = $this->dsElement($document, 'SignatureValue', $signature);
        $this->appendKeyInfo($document, $signature);

        $packageObject = $this->dsElement($document, 'Object', $signature);
        $packageObject->setAttribute('Id', 'idPackageObject');
        $manifest = $this->dsElement($document, 'Manifest', $packageObject);

        $names = array_keys($entries);
        sort($names, SORT_STRING);
        foreach ($names as $name) {
            if ($name === '[Content_Types].xml' || $name === $signatureName || str_ends_with($name, '/')) {
                continue;
            }
            if (!isset($contentTypes[$name])) {
                throw new \RuntimeException("OOXML package has no content type for part: {$name}");
            }

            $contentType = $contentTypes[$name];
            if (!$countersignExisting && $contentType === self::OPC_SIGNATURE_CONTENT_TYPE) {
                continue;
            }
            $reference = $this->dsElement($document, 'Reference', $manifest);
            $reference->setAttribute(
                'URI',
                '/' . $this->opcPartUri($name) . '?ContentType=' . $contentType
            );

            if ($contentType === self::OPC_RELATIONSHIPS_CONTENT_TYPE || str_ends_with($name, '.rels')) {
                $relationships = $this->loadRelationships($entries[$name], $name);
                $selectedRelationships = $this->relationshipElements($relationships);
                if (!$countersignExisting && $name === $originRelationshipsName) {
                    $selectedRelationships = array_values(array_filter(
                        $selectedRelationships,
                        static fn(DOMElement $relationship): bool =>
                            $relationship->getAttribute('Type') !== self::OPC_SIGNATURE_RELATIONSHIP
                            || $relationship->getAttribute('Id') === $signatureRelationshipId
                    ));
                }
                $referenceTransforms = $this->dsElement($document, 'Transforms', $reference);
                $relationshipTransform = $this->dsElement($document, 'Transform', $referenceTransforms);
                $relationshipTransform->setAttribute('Algorithm', self::OPC_RELATIONSHIP_TRANSFORM);

                $selectedIds = [];
                foreach ($selectedRelationships as $relationship) {
                    $selector = $document->createElementNS(
                        self::OPC_SIGNATURE_NS,
                        'mdssi:RelationshipReference'
                    );
                    $relationshipId = $relationship->getAttribute('Id');
                    $selector->setAttribute('SourceId', $relationshipId);
                    $relationshipTransform->appendChild($selector);
                    $selectedIds[$relationshipId] = true;
                }
                $c14nTransform = $this->dsElement($document, 'Transform', $referenceTransforms);
                $c14nTransform->setAttribute('Algorithm', self::C14N);
                $digestInput = $this->relationshipTransform($relationships, $selectedIds);
            } elseif ($this->isXMLContentType($contentType)) {
                $referenceTransforms = $this->dsElement($document, 'Transforms', $reference);
                $c14nTransform = $this->dsElement($document, 'Transform', $referenceTransforms);
                $c14nTransform->setAttribute('Algorithm', self::C14N);
                $digestInput = $this->canonicalizeXML($entries[$name], $name);
            } else {
                $digestInput = $entries[$name];
            }

            $partDigestMethod = $this->dsElement($document, 'DigestMethod', $reference);
            $partDigestMethod->setAttribute('Algorithm', self::SHA256);
            $partDigest = $this->dsElement($document, 'DigestValue', $reference);
            $partDigest->nodeValue = $this->digest($digestInput);
        }

        $properties = $this->dsElement($document, 'SignatureProperties', $packageObject);
        $property = $this->dsElement($document, 'SignatureProperty', $properties);
        $property->setAttribute('Id', 'idSignatureTime');
        $property->setAttribute('Target', '#' . $signatureId);
        $signatureTime = $document->createElementNS(self::OPC_SIGNATURE_NS, 'mdssi:SignatureTime');
        $property->appendChild($signatureTime);
        $format = $document->createElementNS(self::OPC_SIGNATURE_NS, 'mdssi:Format');
        $format->nodeValue = 'YYYY-MM-DDThh:mm:ssTZD';
        $signatureTime->appendChild($format);
        $value = $document->createElementNS(self::OPC_SIGNATURE_NS, 'mdssi:Value');
        $value->nodeValue = $this->opcSigningTime($options['signingTime'] ?? null);
        $signatureTime->appendChild($value);

        $packageDigestValue->nodeValue = $this->digest($this->canonicalizeNode($packageObject));
        $signatureValue->nodeValue = $this->signCanonicalNode($signedInfo);

        $rootXml = $document->saveXML($signature);
        if ($rootXml === false) {
            throw new \RuntimeException('Unable to serialize OPC signature XML');
        }
        // Windows' OPC parser preserves whitespace and permits no text nodes outside Signature.
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' . $rootXml;
    }

    private function signODF(array $entries, array $options): array {
        if (!isset($entries['mimetype'], $entries['META-INF/manifest.xml'])) {
            throw new \RuntimeException('OpenDocument package is missing mimetype or META-INF/manifest.xml');
        }
        if (!$this->isODFMimetype($entries['mimetype'])) {
            throw new \RuntimeException('OpenDocument package has an invalid mimetype');
        }

        $manifest = $this->loadXML($entries['META-INF/manifest.xml'], 'META-INF/manifest.xml');
        $manifestRoot = $manifest->documentElement;
        if ($manifestRoot?->localName !== 'manifest'
            || $manifestRoot->namespaceURI !== self::ODF_MANIFEST_NS) {
            throw new \RuntimeException('OpenDocument package has an invalid manifest namespace');
        }
        $manifestVersion = $manifestRoot->getAttributeNS(self::ODF_MANIFEST_NS, 'version');
        if (!in_array($manifestVersion, ['1.2', '1.3'], true)) {
            throw new \RuntimeException("Unsupported OpenDocument manifest version: {$manifestVersion}");
        }
        $manifestXPath = new DOMXPath($manifest);
        $manifestXPath->registerNamespace('manifest', self::ODF_MANIFEST_NS);
        $rootEntry = $manifestXPath->query(
            '/manifest:manifest/manifest:file-entry[@manifest:full-path="/"]'
        )?->item(0);
        if (!$rootEntry instanceof DOMElement
            || $rootEntry->getAttributeNS(self::ODF_MANIFEST_NS, 'media-type') !== $entries['mimetype']) {
            throw new \RuntimeException('OpenDocument manifest media type does not match mimetype');
        }
        $encryptedEntries = $this->odfEncryptedEntries($manifest);

        if (isset($entries[self::ODF_SIGNATURE_PATH])) {
            $signatures = $this->loadXML($entries[self::ODF_SIGNATURE_PATH], self::ODF_SIGNATURE_PATH, false);
            $root = $signatures->documentElement;
            if ($root === null
                || $root->localName !== 'document-signatures'
                || $root->namespaceURI !== self::ODF_SIGNATURE_NS) {
                throw new \RuntimeException('OpenDocument signature file has an invalid root element');
            }
        } else {
            $signatures = new DOMDocument('1.0', 'UTF-8');
            $signatures->preserveWhiteSpace = true;
            $root = $signatures->createElementNS(self::ODF_SIGNATURE_NS, 'dsig:document-signatures');
            $root->setAttributeNS(self::ODF_SIGNATURE_NS, 'dsig:version', '1.2');
            $signatures->appendChild($root);
        }

        $number = 1;
        $existingIds = [];
        foreach ($root->getElementsByTagNameNS(self::XMLDSIG_NS, 'Signature') as $existing) {
            $existingId = $existing->getAttribute('Id');
            if ($existingId !== '') {
                $existingIds[$existingId] = true;
            }
            if (preg_match('/^FoxySignature(\d+)$/', $existing->getAttribute('Id'), $match)) {
                $number = max($number, (int)$match[1] + 1);
            }
        }
        $signatureId = $this->stringOption($options, 'signatureId', "FoxySignature{$number}");
        $this->validateXMLId($signatureId, 'ODF signatureId');
        if (isset($existingIds[$signatureId])) {
            throw new \InvalidArgumentException("ODF signatureId is already in use: {$signatureId}");
        }

        $signature = $signatures->createElementNS(self::XMLDSIG_NS, 'ds:Signature');
        $signature->setAttribute('Id', $signatureId);
        $root->appendChild($signature);
        $signedInfo = $this->dsElement($signatures, 'SignedInfo', $signature, 'ds');
        $canonicalization = $this->dsElement($signatures, 'CanonicalizationMethod', $signedInfo, 'ds');
        $canonicalization->setAttribute('Algorithm', self::C14N);
        $signatureMethod = $this->dsElement($signatures, 'SignatureMethod', $signedInfo, 'ds');
        $signatureMethod->setAttribute('Algorithm', self::RSA_SHA256);

        $names = array_keys($entries);
        sort($names, SORT_STRING);
        foreach ($names as $name) {
            if ($name === self::ODF_SIGNATURE_PATH || str_ends_with($name, '/')) {
                continue;
            }

            $reference = $this->dsElement($signatures, 'Reference', $signedInfo, 'ds');
            $reference->setAttribute('URI', $this->encodePackagePath($name));
            if (!isset($encryptedEntries[$name]) && $this->isODFXMLPath($name)) {
                $transforms = $this->dsElement($signatures, 'Transforms', $reference, 'ds');
                $transform = $this->dsElement($signatures, 'Transform', $transforms, 'ds');
                $transform->setAttribute('Algorithm', self::C14N);
                $digestInput = $this->canonicalizeXML($entries[$name], $name);
            } else {
                $digestInput = $entries[$name];
            }
            $digestMethod = $this->dsElement($signatures, 'DigestMethod', $reference, 'ds');
            $digestMethod->setAttribute('Algorithm', self::SHA256);
            $digestValue = $this->dsElement($signatures, 'DigestValue', $reference, 'ds');
            $digestValue->nodeValue = $this->digest($digestInput);
        }

        $signatureValue = $this->dsElement($signatures, 'SignatureValue', $signature, 'ds');
        $this->appendKeyInfo($signatures, $signature, 'ds');
        $signatureValue->nodeValue = $this->signCanonicalNode($signedInfo);

        return [self::ODF_SIGNATURE_PATH => $this->saveXML($signatures)];
    }

    private function odfEncryptedEntries(DOMDocument $manifest): array {
        $xpath = new DOMXPath($manifest);
        $xpath->registerNamespace('manifest', self::ODF_MANIFEST_NS);
        $encrypted = [];
        foreach ($xpath->query('//manifest:file-entry[manifest:encryption-data]') ?: [] as $entry) {
            if (!$entry instanceof DOMElement) {
                continue;
            }
            $path = $entry->getAttributeNS(self::ODF_MANIFEST_NS, 'full-path');
            if ($path !== '') {
                $encrypted[$path] = true;
            }
        }
        return $encrypted;
    }

    private function loadRelationships(string $xml, string $context): DOMDocument {
        $document = $this->loadXML($xml, $context);
        if ($document->documentElement?->localName !== 'Relationships'
            || $document->documentElement->namespaceURI !== self::RELATIONSHIPS_NS) {
            throw new \RuntimeException("Invalid relationships document: {$context}");
        }
        foreach ($this->relationshipElements($document) as $relationship) {
            foreach (['Id', 'Type', 'Target'] as $attribute) {
                if (!$relationship->hasAttribute($attribute) || $relationship->getAttribute($attribute) === '') {
                    throw new \RuntimeException("Relationship in {$context} is missing {$attribute}");
                }
            }
        }
        return $document;
    }

    private function newRelationshipsDocument(): DOMDocument {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;
        $document->appendChild($document->createElementNS(self::RELATIONSHIPS_NS, 'Relationships'));
        return $document;
    }

    private function relationshipElements(DOMDocument $document): array {
        $relationships = [];
        foreach ($document->documentElement?->childNodes ?? [] as $node) {
            if ($node instanceof DOMElement
                && $node->localName === 'Relationship'
                && $node->namespaceURI === self::RELATIONSHIPS_NS) {
                $relationships[] = $node;
            }
        }
        return $relationships;
    }

    private function findRelationshipByType(DOMDocument $document, string $type): ?DOMElement {
        foreach ($this->relationshipElements($document) as $relationship) {
            if ($relationship->getAttribute('Type') === $type) {
                return $relationship;
            }
        }
        return null;
    }

    private function nextRelationshipId(DOMDocument $document, string $preferred): string {
        $ids = [];
        foreach ($this->relationshipElements($document) as $relationship) {
            $ids[$relationship->getAttribute('Id')] = true;
        }
        if (!isset($ids[$preferred])) {
            return $preferred;
        }
        for ($suffix = 2; ; $suffix++) {
            if (!isset($ids[$preferred . $suffix])) {
                return $preferred . $suffix;
            }
        }
    }

    private function ensureContentType(
        DOMDocument $document,
        string $partName,
        ?string $extension,
        string $contentType
    ): void {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ct', self::CONTENT_TYPES_NS);

        $normalizedPartName = ltrim($partName, '/');
        $partKey = $this->opcComparisonKey($this->opcPartUri($normalizedPartName));
        foreach ($xpath->query('/ct:Types/ct:Override') ?: [] as $override) {
            if (!$override instanceof DOMElement) {
                continue;
            }
            $existingPartName = ltrim($override->getAttribute('PartName'), '/');
            if ($existingPartName !== ''
                && $this->opcComparisonKey($this->opcPartUri($existingPartName)) === $partKey) {
                if ($override->getAttribute('ContentType') !== $contentType) {
                    throw new \RuntimeException("Conflicting OOXML content type for {$partName}");
                }
                return;
            }
        }

        if ($extension !== null && $extension !== '') {
            foreach ($xpath->query('/ct:Types/ct:Default') ?: [] as $default) {
                if ($default instanceof DOMElement
                    && strcasecmp($default->getAttribute('Extension'), $extension) === 0) {
                    if ($default->getAttribute('ContentType') === $contentType) {
                        return;
                    }
                    // An Override is required when this extension already has another default type.
                    break;
                }
            }
            $hasDefault = false;
            foreach ($xpath->query('/ct:Types/ct:Default') ?: [] as $default) {
                if ($default instanceof DOMElement
                    && strcasecmp($default->getAttribute('Extension'), $extension) === 0) {
                    $hasDefault = true;
                    break;
                }
            }
            if (!$hasDefault) {
                $default = $document->createElementNS(self::CONTENT_TYPES_NS, 'Default');
                $default->setAttribute('Extension', $extension);
                $default->setAttribute('ContentType', $contentType);
                $document->documentElement->appendChild($default);
                return;
            }
        }

        $override = $document->createElementNS(self::CONTENT_TYPES_NS, 'Override');
        $override->setAttribute('PartName', $partName);
        $override->setAttribute('ContentType', $contentType);
        $document->documentElement->appendChild($override);
    }

    private function contentTypeMap(DOMDocument $document): array {
        $defaults = [];
        $overrides = [];
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ct', self::CONTENT_TYPES_NS);
        foreach ($xpath->query('/ct:Types/ct:Default') ?: [] as $node) {
            if ($node instanceof DOMElement) {
                $extension = strtolower($node->getAttribute('Extension'));
                $contentType = $node->getAttribute('ContentType');
                if ($extension === '' || $contentType === '') {
                    throw new \RuntimeException('OOXML package has an invalid default content type');
                }
                if (isset($defaults[$extension]) && $defaults[$extension] !== $contentType) {
                    throw new \RuntimeException("OOXML package has conflicting defaults for .{$extension}");
                }
                $defaults[$extension] = $contentType;
            }
        }
        foreach ($xpath->query('/ct:Types/ct:Override') ?: [] as $node) {
            if ($node instanceof DOMElement) {
                $partName = $node->getAttribute('PartName');
                $contentType = $node->getAttribute('ContentType');
                if (!str_starts_with($partName, '/') || $contentType === '') {
                    throw new \RuntimeException('OOXML package has an invalid content type override');
                }
                $name = $this->opcPartUri(ltrim($partName, '/'));
                $key = $this->opcComparisonKey($name);
                if (isset($overrides[$key]) && $overrides[$key] !== $contentType) {
                    throw new \RuntimeException("OOXML package has conflicting overrides for {$partName}");
                }
                $overrides[$key] = $contentType;
            }
        }

        return ['defaults' => $defaults, 'overrides' => $overrides];
    }

    private function resolveContentTypes(array $entries, array $contentTypeData): array {
        $resolved = [];
        foreach (array_keys($entries) as $name) {
            if ($name === '[Content_Types].xml' || str_ends_with($name, '/')) {
                continue;
            }
            $key = $this->opcComparisonKey($name);
            if (isset($contentTypeData['overrides'][$key])) {
                $resolved[$name] = $contentTypeData['overrides'][$key];
                continue;
            }
            $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            if (isset($contentTypeData['defaults'][$extension])) {
                $resolved[$name] = $contentTypeData['defaults'][$extension];
            }
        }
        return $resolved;
    }

    private function relationshipTransform(DOMDocument $relationships, ?array $selectedIds = null): string {
        $output = new DOMDocument('1.0', 'UTF-8');
        $root = $output->createElementNS(self::RELATIONSHIPS_NS, 'Relationships');
        $output->appendChild($root);

        $elements = $this->relationshipElements($relationships);
        if ($selectedIds !== null) {
            $elements = array_values(array_filter(
                $elements,
                static fn(DOMElement $relationship): bool => isset($selectedIds[$relationship->getAttribute('Id')])
            ));
        }
        usort(
            $elements,
            static fn(DOMElement $left, DOMElement $right): int => strcmp(
                $left->getAttribute('Id'),
                $right->getAttribute('Id')
            )
        );
        foreach ($elements as $relationship) {
            $copy = $output->createElementNS(self::RELATIONSHIPS_NS, 'Relationship');
            foreach (['Id', 'Type', 'Target'] as $attribute) {
                if ($relationship->hasAttribute($attribute)) {
                    $copy->setAttribute($attribute, $relationship->getAttribute($attribute));
                }
            }
            $copy->setAttribute(
                'TargetMode',
                $relationship->hasAttribute('TargetMode')
                    ? $relationship->getAttribute('TargetMode')
                    : 'Internal'
            );
            $root->appendChild($copy);
        }
        return $this->canonicalizeNode($root);
    }

    private function loadXML(string $xml, string $context, bool $removeBlankNodes = true): DOMDocument {
        $document = new DOMDocument();
        $document->preserveWhiteSpace = !$removeBlankNodes;
        $previous = libxml_use_internal_errors(true);
        try {
            if (!$document->loadXML($xml, LIBXML_NONET | ($removeBlankNodes ? LIBXML_NOBLANKS : 0))) {
                $error = libxml_get_last_error();
                $message = $error === false ? 'invalid XML' : trim($error->message);
                throw new \RuntimeException("Unable to parse {$context}: {$message}");
            }
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        return $document;
    }

    private function saveXML(DOMDocument $document): string {
        $document->formatOutput = false;
        $xml = $document->saveXML();
        if ($xml === false) {
            throw new \RuntimeException('Unable to serialize XML signature data');
        }
        return $xml;
    }

    private function canonicalizeXML(string $xml, string $context): string {
        return $this->canonicalizeNode($this->loadXML($xml, $context, false));
    }

    private function canonicalizeNode(?DOMNode $node): string {
        if ($node === null) {
            throw new \RuntimeException('Cannot canonicalize an empty XML document');
        }
        $canonical = $node->C14N(false, false);
        if ($canonical === false) {
            throw new \RuntimeException('Unable to canonicalize XML');
        }
        return $canonical;
    }

    private function dsElement(
        DOMDocument $document,
        string $localName,
        DOMElement $parent,
        string $prefix = ''
    ): DOMElement {
        $qualifiedName = $prefix === '' ? $localName : $prefix . ':' . $localName;
        $element = $document->createElementNS(self::XMLDSIG_NS, $qualifiedName);
        $parent->appendChild($element);
        return $element;
    }

    private function appendKeyInfo(DOMDocument $document, DOMElement $signature, string $prefix = ''): void {
        $keyInfo = $this->dsElement($document, 'KeyInfo', $signature, $prefix);
        $x509Data = $this->dsElement($document, 'X509Data', $keyInfo, $prefix);
        foreach (array_merge([$this->certDer], $this->extraCertsDer) as $certificate) {
            $x509Certificate = $this->dsElement($document, 'X509Certificate', $x509Data, $prefix);
            $x509Certificate->nodeValue = base64_encode($certificate);
        }
    }

    private function signCanonicalNode(DOMElement $element): string {
        $digest = hex2bin(Hash::hash('sha256', $this->canonicalizeNode($element)));
        return base64_encode($this->signerKey->sign($digest));
    }

    private function digest(string $data): string {
        return base64_encode(hex2bin(Hash::hash('sha256', $data)));
    }

    private function isXMLContentType(string $contentType): bool {
        $mediaType = strtolower(trim(explode(';', $contentType, 2)[0]));
        return $mediaType === 'application/xml'
            || $mediaType === 'text/xml'
            || str_ends_with($mediaType, '+xml');
    }

    private function isODFXMLPath(string $path): bool {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return $extension === 'xml' || $extension === 'rdf';
    }

    private function isODFMimetype(string $mimetype): bool {
        return preg_match(
            '/^application\/vnd\.oasis\.opendocument\.[a-z0-9][a-z0-9.-]*$/D',
            $mimetype
        ) === 1;
    }

    private function encodePackagePath(string $path): string {
        return implode('/', array_map('rawurlencode', explode('/', $path)));
    }

    private function validateOPCPartNames(array $names): void {
        $seen = [];
        foreach ($names as $name) {
            if ($name === '[Content_Types].xml') {
                continue;
            }
            $this->opcPartUri($name);
            $key = $this->opcComparisonKey($name);
            if (isset($seen[$key])) {
                throw new \RuntimeException("OOXML package has equivalent part names: {$seen[$key]} and {$name}");
            }
            $seen[$key] = $name;
        }
    }

    private function opcPartUri(string $name): string {
        if ($name === ''
            || str_starts_with($name, '/')
            || str_ends_with($name, '/')
            || str_contains($name, '\\')
            || str_contains($name, '?')
            || str_contains($name, '#')
            || !preg_match("~^(?:[A-Za-z0-9._\\~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2}|/)+$~D", $name)) {
            throw new \RuntimeException("Invalid OOXML part name: {$name}");
        }
        foreach (explode('/', $name) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw new \RuntimeException("Invalid OOXML part name: {$name}");
            }
        }
        return $name;
    }

    private function opcComparisonKey(string $name): string {
        $normalized = preg_replace_callback(
            '/%[0-9A-Fa-f]{2}/',
            static fn(array $match): string => strtoupper($match[0]),
            $name
        );
        return strtolower((string)$normalized);
    }

    private function resolveRelationshipTarget(string $sourcePart, string $target): string {
        $path = preg_split('/[?#]/', $target, 2)[0] ?? '';
        if ($path === '' || str_contains($path, '\\')) {
            throw new \RuntimeException("Invalid package relationship target: {$target}");
        }
        $base = $sourcePart === '' ? '' : dirname($sourcePart);
        $combined = str_starts_with($path, '/') ? ltrim($path, '/') : (($base === '.' || $base === '') ? $path : $base . '/' . $path);
        $segments = [];
        foreach (explode('/', $combined) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    throw new \RuntimeException("Relationship target escapes the package: {$target}");
                }
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }
        if ($segments === []) {
            throw new \RuntimeException("Invalid package relationship target: {$target}");
        }
        return $this->opcPartUri(implode('/', $segments));
    }

    private function validateXMLId(string $id, string $context): void {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9._-]*$/', $id)) {
            throw new \InvalidArgumentException("{$context} is not a valid XML ID");
        }
    }

    private function validateODFMimetypeEntry(string $package): void {
        if (strlen($package) < 38 || substr($package, 0, 4) !== "PK\x03\x04") {
            throw new \RuntimeException('Signed OpenDocument package has an invalid first ZIP entry');
        }
        $method = unpack('v', substr($package, 8, 2))[1];
        $nameLength = unpack('v', substr($package, 26, 2))[1];
        $extraLength = unpack('v', substr($package, 28, 2))[1];
        $name = substr($package, 30, $nameLength);
        if ($name !== 'mimetype' || $method !== ZipArchive::CM_STORE || $extraLength !== 0) {
            throw new \RuntimeException('OpenDocument mimetype must remain first, uncompressed, and without extra data');
        }
    }
}
