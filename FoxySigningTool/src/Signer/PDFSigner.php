<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{Hash, PEM, RSA, X509Certificate};
use FoxySigningTool\PKCS7;

final class PDFSigner {
    private const BYTE_RANGE_PLACEHOLDER = '[0 00000000000000000000 00000000000000000000 00000000000000000000]';

    private RSA $signerKey;
    private string $certPem;
    private array $extraCerts;
    private array $xrefEntries = [];
    private array $objectCache = [];
    private array $objectStreamCache = [];

    public function __construct(object $signerKey, string $certPem, string $hashAlgo = 'sha256', array $extraCerts = []) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('PDF signing requires an RSA private key');
        }
        if (strtolower($hashAlgo) !== 'sha256') {
            throw new \InvalidArgumentException('PDF signing currently supports SHA-256 only');
        }

        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY'));
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('PDF signing requires an RSA certificate', 0, $exception);
        }
        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('PDF signing key does not match the certificate');
        }
        foreach ($extraCerts as $extraCert) {
            if (!is_string($extraCert)) {
                throw new \InvalidArgumentException('Each extra certificate must be PEM encoded');
            }
            X509Certificate::fromPEM($extraCert);
            PEM::decode($extraCert);
        }

        $this->signerKey = $signerKey;
        $this->certPem = $certPem;
        $this->extraCerts = $extraCerts;
    }

    public function signFile(string $inputPath, ?string $outputPath = null, array $options = []): string {
        $pdfData = @file_get_contents($inputPath);
        if ($pdfData === false) {
            throw new \RuntimeException("Unable to read PDF: {$inputPath}");
        }

        $signed = $this->signBinary($pdfData, $options);
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
                throw new \RuntimeException("Unable to write the complete signed PDF: {$path}");
            }
            if (@rename($temporary, $path)) {
                $temporary = '';
                return;
            }

            $backup = tempnam($directory, '.foxy-backup-');
            if ($backup === false || !@unlink($backup) || !@rename($path, $backup)) {
                throw new \RuntimeException("Unable to replace signed PDF: {$path}");
            }
            try {
                if (!@rename($temporary, $path)) {
                    @rename($backup, $path);
                    throw new \RuntimeException("Unable to replace signed PDF: {$path}");
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

    public function signBinary(string $pdfData, array $options = []): string {
        $headerPosition = strpos(substr($pdfData, 0, 1024), '%PDF-');
        if ($headerPosition === false) {
            throw new \RuntimeException('Input is not a PDF document');
        }

        $state = $this->readDocumentState($pdfData);
        $reserve = $this->signatureReservation($options);

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $revision = $this->buildIncrementalRevision($pdfData, $state, $reserve, $options);
            $unsigned = $revision['pdf'];
            $signatureStart = $revision['signatureStart'];
            $signatureEnd = $revision['signatureEnd'];
            $contentsMarker = '/Contents <' . str_repeat('0', $reserve * 2) . '>';
            $contentsPos = strpos($unsigned, $contentsMarker, $signatureStart);
            $rangePos = strpos($unsigned, self::BYTE_RANGE_PLACEHOLDER, $signatureStart);
            if ($contentsPos === false || $rangePos === false
                || $contentsPos >= $signatureEnd || $rangePos >= $signatureEnd) {
                throw new \RuntimeException('Unable to locate PDF signature placeholders');
            }

            // Exclude the complete hexadecimal string token, including its delimiters.
            $gapStart = $contentsPos + strlen('/Contents ');
            $gapEnd = $gapStart + 2 + ($reserve * 2);
            $byteRange = sprintf(
                '[0 %020d %020d %020d]',
                $gapStart,
                $gapEnd,
                strlen($unsigned) - $gapEnd
            );
            if (strlen($byteRange) !== strlen(self::BYTE_RANGE_PLACEHOLDER)) {
                throw new \RuntimeException('PDF is too large for the signature byte range');
            }

            $unsigned = substr_replace($unsigned, $byteRange, $rangePos, strlen(self::BYTE_RANGE_PLACEHOLDER));
            $signedBytes = substr($unsigned, 0, $gapStart) . substr($unsigned, $gapEnd);
            $cms = PKCS7::buildDetachedSignature(
                $signedBytes,
                $this->signerKey,
                $this->certPem,
                'sha256',
                $this->extraCerts
            );

            if (strlen($cms) <= $reserve) {
                $contentsHex = strtoupper(bin2hex($cms)) . str_repeat('0', ($reserve - strlen($cms)) * 2);
                return substr_replace($unsigned, $contentsHex, $gapStart + 1, $reserve * 2);
            }

            $reserve = (int)(ceil((strlen($cms) + 2048) / 1024) * 1024);
        }

        throw new \RuntimeException('Unable to reserve enough space for the PDF signature');
    }

    private function signatureReservation(array $options): int {
        if (isset($options['signatureSize'])) {
            if (!is_int($options['signatureSize'])) {
                throw new \InvalidArgumentException('PDF signatureSize must be an integer');
            }
            $reserve = $options['signatureSize'];
            if ($reserve < 1024) {
                throw new \InvalidArgumentException('PDF signatureSize must be at least 1024 bytes');
            }
            return $reserve;
        }

        $certificateBytes = strlen(PEM::decode($this->certPem)['data']);
        foreach ($this->extraCerts as $extraCert) {
            $certificateBytes += strlen(PEM::decode($extraCert)['data']);
        }

        return max(8192, (int)(ceil(($certificateBytes + 4096) / 1024) * 1024));
    }

    private function textOption(array $options, string $name, string $default): string {
        if (!array_key_exists($name, $options)) {
            return $default;
        }
        if (!is_string($options[$name])) {
            throw new \InvalidArgumentException("PDF {$name} must be a string");
        }
        return $options[$name];
    }

    private function readDocumentState(string $pdf): array {
        if (!preg_match_all('/startxref\s+(\d+)\s+%%EOF/s', $pdf, $matches, PREG_SET_ORDER)) {
            throw new \RuntimeException('PDF has no valid startxref marker');
        }

        $latestXref = (int)$matches[array_key_last($matches)][1];
        if ($latestXref < 0 || $latestXref >= strlen($pdf)) {
            throw new \RuntimeException('PDF startxref offset is outside the file');
        }

        $this->xrefEntries = [];
        $this->objectCache = [];
        $this->objectStreamCache = [];
        $xref = $this->readCrossReferenceChain($pdf, $latestXref);
        $trailerValues = $xref['trailer'];
        $this->xrefEntries = $xref['entries'];

        if (isset($trailerValues['Encrypt'])) {
            throw new \RuntimeException('Encrypted PDFs are not supported');
        }
        if (!isset($trailerValues['Root']) || !isset($trailerValues['Size'])) {
            throw new \RuntimeException('PDF trailer is missing Root or Size');
        }

        $rootRef = $this->parseReference($trailerValues['Root'], 'PDF Root');
        $catalog = $this->indirectDictionary($pdf, $rootRef);
        $this->assertSigningPermissions($pdf, $catalog);
        $pagesEntry = $this->findDictionaryEntry($catalog, 'Pages');
        if ($pagesEntry === null) {
            throw new \RuntimeException('PDF catalog has no Pages tree');
        }
        $pagesRef = $this->parseReference($pagesEntry['raw'], 'PDF Pages');
        $firstPage = $this->findFirstPage($pdf, $pagesRef);

        $oldSize = $this->nonNegativeInteger($trailerValues['Size'], 'PDF trailer Size');
        if ($oldSize < 1) {
            throw new \RuntimeException('PDF trailer has an invalid Size');
        }

        $maxObject = $this->xrefEntries === [] ? 0 : max(array_keys($this->xrefEntries));

        return [
            'latestXref' => $latestXref,
            'trailer' => $trailerValues,
            'rootRef' => $rootRef,
            'catalog' => $catalog,
            'firstPageRef' => $firstPage['ref'],
            'firstPage' => $firstPage['dictionary'],
            'nextObject' => max($oldSize, $maxObject + 1),
            'updatedId' => isset($trailerValues['ID'])
                ? $this->updatedFileIdentifier($trailerValues['ID'], $pdf)
                : null,
        ];
    }

    private function updatedFileIdentifier(string $rawId, string $pdf): string {
        $values = $this->arrayValues(trim($rawId));
        if (count($values) !== 2) {
            throw new \RuntimeException('PDF trailer has an invalid ID array');
        }
        $newId = strtoupper(substr(Hash::hash('sha256', $pdf . random_bytes(32)), 0, 32));
        return '[' . $values[0] . ' <' . $newId . '>]';
    }

    private function assertSigningPermissions(string $pdf, string $catalog): void {
        $permissions = $this->findDictionaryEntry($catalog, 'Perms');
        if ($permissions !== null) {
            $permissionsDictionary = $this->resolveDictionaryValue(
                $pdf,
                $permissions['raw'],
                'PDF permissions'
            );
            if ($this->findDictionaryEntry($permissionsDictionary, 'DocMDP') !== null) {
                throw new \RuntimeException(
                    'PDF has a DocMDP certification signature; adding a new field could violate its permissions'
                );
            }
        }

        $acroFormEntry = $this->findDictionaryEntry($catalog, 'AcroForm');
        if ($acroFormEntry === null) {
            return;
        }
        $acroForm = $this->resolveDictionaryValue($pdf, $acroFormEntry['raw'], 'PDF AcroForm');
        $fieldsEntry = $this->findDictionaryEntry($acroForm, 'Fields');
        if ($fieldsEntry === null) {
            return;
        }

        $pending = $this->arrayValues($this->resolveArray($pdf, $fieldsEntry['raw']));
        $visited = [];
        $processed = 0;
        while ($pending !== []) {
            if (++$processed > 10000) {
                throw new \RuntimeException('PDF form field tree is too large');
            }
            $fieldValue = array_shift($pending);
            $fieldKey = trim($fieldValue);
            if (preg_match('/^\d+[ \t\r\n]+\d+[ \t\r\n]+R$/', $fieldKey)) {
                $ref = $this->parseReference($fieldKey, 'PDF form field');
                $fieldKey = $this->formatReference($ref);
                if (isset($visited[$fieldKey])) {
                    continue;
                }
                $visited[$fieldKey] = true;
                $field = $this->indirectDictionary($pdf, $ref);
            } elseif (str_starts_with($fieldKey, '<<')) {
                $field = $this->extractDictionary($fieldKey);
            } else {
                throw new \RuntimeException('PDF AcroForm contains an invalid field entry');
            }

            $kids = $this->findDictionaryEntry($field, 'Kids');
            if ($kids !== null) {
                $pending = array_merge(
                    $pending,
                    $this->arrayValues($this->resolveArray($pdf, $kids['raw']))
                );
            }

            $value = $this->findDictionaryEntry($field, 'V');
            if ($value === null || trim($value['raw']) === 'null') {
                continue;
            }
            if ($this->findDictionaryEntry($field, 'Lock') !== null) {
                throw new \RuntimeException(
                    'PDF has an active signature field lock; adding another field is not supported safely'
                );
            }

            $signature = $this->resolveDictionaryValue($pdf, $value['raw'], 'PDF signature field value');
            $references = $this->findDictionaryEntry($signature, 'Reference');
            if ($references === null) {
                continue;
            }
            foreach ($this->arrayValues($this->resolveArray($pdf, $references['raw'])) as $referenceValue) {
                $reference = $this->resolveDictionaryValue($pdf, $referenceValue, 'PDF signature reference');
                $method = $this->findDictionaryEntry($reference, 'TransformMethod');
                if ($method !== null
                    && $this->parseName($method['raw'], 'PDF signature transform') === 'FieldMDP') {
                    throw new \RuntimeException(
                        'PDF has FieldMDP restrictions; adding another signature field is not supported safely'
                    );
                }
            }
        }
    }

    private function resolveDictionaryValue(string $pdf, string $raw, string $context): string {
        $raw = trim($raw);
        if (str_starts_with($raw, '<<')) {
            return $this->extractDictionary($raw);
        }
        return $this->indirectDictionary($pdf, $this->parseReference($raw, $context));
    }

    private function arrayValues(string $array): array {
        $start = strpos($array, '[');
        if ($start === false) {
            throw new \RuntimeException('Expected a PDF array');
        }
        $end = $this->compositeEnd($array, $start);
        $position = $start + 1;
        $values = [];
        while ($position < $end - 1) {
            $position = $this->skipWhitespaceAndComments($array, $position);
            if ($position >= $end - 1 || ($array[$position] ?? '') === ']') {
                break;
            }
            $valueEnd = $this->valueEnd($array, $position);
            $values[] = substr($array, $position, $valueEnd - $position);
            $position = $valueEnd;
        }
        return $values;
    }

    private function readCrossReferenceChain(string $pdf, int $latestOffset): array {
        $entries = [];
        $trailerValues = [];
        $visited = [];
        $offset = $latestOffset;

        for ($revision = 0; ; $revision++) {
            if ($revision >= 1000) {
                throw new \RuntimeException('PDF has too many incremental revisions');
            }
            if (isset($visited[$offset])) {
                throw new \RuntimeException('PDF cross-reference chain contains a cycle');
            }
            $visited[$offset] = true;

            $section = $this->readCrossReferenceSection($pdf, $offset);
            foreach ($section['entries'] as $number => $entry) {
                if (!array_key_exists($number, $entries)) {
                    $entries[$number] = $entry;
                }
            }
            $this->mergeTrailerValues($trailerValues, $section['trailer']);

            $xrefStream = $this->findDictionaryEntry($section['trailer'], 'XRefStm');
            if ($xrefStream !== null) {
                $streamOffset = $this->nonNegativeInteger($xrefStream['raw'], 'PDF XRefStm offset');
                if (isset($visited[$streamOffset])) {
                    throw new \RuntimeException('PDF hybrid cross-reference data contains a cycle');
                }
                $visited[$streamOffset] = true;
                $supplement = $this->readCrossReferenceStream($pdf, $streamOffset);
                foreach ($supplement['entries'] as $number => $entry) {
                    if (!array_key_exists($number, $entries)
                        || ($entries[$number]['type'] === 0 && $entry['type'] !== 0)) {
                        $entries[$number] = $entry;
                    }
                }
                $this->mergeTrailerValues($trailerValues, $supplement['trailer']);
            }

            $previous = $this->findDictionaryEntry($section['trailer'], 'Prev');
            if ($previous === null) {
                break;
            }
            $offset = $this->nonNegativeInteger($previous['raw'], 'PDF Prev offset');
            if ($offset >= strlen($pdf)) {
                throw new \RuntimeException('PDF Prev offset is outside the file');
            }
        }

        return ['entries' => $entries, 'trailer' => $trailerValues];
    }

    private function mergeTrailerValues(array &$values, string $trailer): void {
        foreach (['Root', 'Size', 'Info', 'ID', 'Encrypt'] as $key) {
            if (array_key_exists($key, $values)) {
                continue;
            }
            $entry = $this->findDictionaryEntry($trailer, $key);
            if ($entry !== null) {
                $values[$key] = $entry['raw'];
            }
        }
    }

    private function readCrossReferenceSection(string $pdf, int $offset): array {
        if ($offset < 0 || $offset >= strlen($pdf)) {
            throw new \RuntimeException('PDF cross-reference offset is outside the file');
        }
        $position = $this->skipWhitespaceAndComments($pdf, $offset);
        if (substr($pdf, $position, 4) === 'xref'
            && $this->isDelimiter($pdf[$position + 4] ?? "\x00")) {
            return $this->readClassicCrossReference($pdf, $position);
        }
        return $this->readCrossReferenceStream($pdf, $position);
    }

    private function readClassicCrossReference(string $pdf, int $position): array {
        $position += 4;
        $entries = [];
        $length = strlen($pdf);

        while ($position < $length) {
            $position = $this->skipWhitespaceAndComments($pdf, $position);
            if (substr($pdf, $position, 7) === 'trailer'
                && $this->isDelimiter($pdf[$position + 7] ?? "\x00")) {
                $dictionaryStart = $this->skipWhitespaceAndComments($pdf, $position + 7);
                if (substr($pdf, $dictionaryStart, 2) !== '<<') {
                    throw new \RuntimeException('PDF cross-reference trailer has no dictionary');
                }
                $dictionaryEnd = $this->compositeEnd($pdf, $dictionaryStart);
                return [
                    'entries' => $entries,
                    'trailer' => substr($pdf, $dictionaryStart, $dictionaryEnd - $dictionaryStart),
                ];
            }

            if (!preg_match('/^(\d+)[ \t]+(\d+)/A', substr($pdf, $position), $header)) {
                throw new \RuntimeException('PDF cross-reference subsection header is invalid');
            }
            $firstObject = (int)$header[1];
            $count = (int)$header[2];
            if ($count < 0 || $count > 10000000 || $firstObject > PHP_INT_MAX - $count) {
                throw new \RuntimeException('PDF cross-reference subsection is too large');
            }
            $position += strlen($header[0]);

            for ($index = 0; $index < $count; $index++) {
                $position = $this->skipWhitespaceAndComments($pdf, $position);
                if (!preg_match(
                    '/^(\d+)[ \t]+(\d+)[ \t]+([nf])(?:[ \t\r\n]|$)/A',
                    substr($pdf, $position),
                    $record
                )) {
                    throw new \RuntimeException('PDF cross-reference entry is invalid');
                }
                $number = $firstObject + $index;
                if (array_key_exists($number, $entries)) {
                    throw new \RuntimeException("PDF cross-reference contains duplicate object {$number}");
                }
                $entryOffset = $this->nonNegativeInteger($record[1], 'PDF object offset');
                $generation = $this->nonNegativeInteger($record[2], 'PDF object generation');
                if ($generation > 65535) {
                    throw new \RuntimeException('PDF object generation exceeds 65535');
                }
                $entries[$number] = $record[3] === 'n'
                    ? ['type' => 1, 'offset' => $entryOffset, 'generation' => $generation]
                    : ['type' => 0, 'next' => $entryOffset, 'generation' => $generation];
                $position += strlen($record[0]);
            }
        }

        throw new \RuntimeException('PDF cross-reference table has no trailer');
    }

    private function readCrossReferenceStream(string $pdf, int $offset): array {
        $object = $this->readIndirectObjectAtOffset($pdf, $offset, false);
        if ($object['stream'] === null || $object['dictionary'] === null) {
            throw new \RuntimeException("PDF cross-reference data at {$offset} is not a stream");
        }
        $type = $this->findDictionaryEntry($object['dictionary'], 'Type');
        if ($type !== null && $this->parseName($type['raw'], 'PDF xref stream type') !== 'XRef') {
            throw new \RuntimeException('PDF startxref does not reference an xref stream');
        }

        $widthEntry = $this->findDictionaryEntry($object['dictionary'], 'W');
        if ($widthEntry === null) {
            throw new \RuntimeException('PDF xref stream has no W array');
        }
        $widthValues = $this->arrayValues($this->resolveDirectArray($widthEntry['raw'], 'PDF xref W'));
        if (count($widthValues) !== 3) {
            throw new \RuntimeException('PDF xref W array must contain three integers');
        }
        $widths = array_map(
            fn(string $value): int => $this->nonNegativeInteger($value, 'PDF xref field width'),
            $widthValues
        );
        if (max($widths) > 8 || array_sum($widths) < 1) {
            throw new \RuntimeException('PDF xref stream has invalid field widths');
        }

        $sizeEntry = $this->findDictionaryEntry($object['dictionary'], 'Size');
        if ($sizeEntry === null) {
            throw new \RuntimeException('PDF xref stream has no Size');
        }
        $size = $this->nonNegativeInteger($sizeEntry['raw'], 'PDF xref Size');
        $indexEntry = $this->findDictionaryEntry($object['dictionary'], 'Index');
        $indexValues = $indexEntry === null
            ? ['0', (string)$size]
            : $this->arrayValues($this->resolveDirectArray($indexEntry['raw'], 'PDF xref Index'));
        if (count($indexValues) === 0 || count($indexValues) % 2 !== 0) {
            throw new \RuntimeException('PDF xref Index array is invalid');
        }

        $decoded = $this->decodeStream($pdf, $object['stream'], $object['dictionary']);
        $rowWidth = array_sum($widths);
        $cursor = 0;
        $entries = [];
        for ($pair = 0; $pair < count($indexValues); $pair += 2) {
            $first = $this->nonNegativeInteger($indexValues[$pair], 'PDF xref Index start');
            $count = $this->nonNegativeInteger($indexValues[$pair + 1], 'PDF xref Index count');
            if ($count > 10000000 || $first > PHP_INT_MAX - $count) {
                throw new \RuntimeException('PDF xref stream subsection is too large');
            }
            for ($index = 0; $index < $count; $index++) {
                if ($cursor + $rowWidth > strlen($decoded)) {
                    throw new \RuntimeException('PDF xref stream data is truncated');
                }
                $fields = [];
                for ($field = 0; $field < 3; $field++) {
                    $fieldBytes = substr($decoded, $cursor, $widths[$field]);
                    $cursor += $widths[$field];
                    $fields[$field] = $widths[$field] === 0
                        ? ($field === 0 ? 1 : 0)
                        : $this->unsignedBytes($fieldBytes, 'PDF xref stream field');
                }
                $number = $first + $index;
                $entries[$number] = match ($fields[0]) {
                    0 => ['type' => 0, 'next' => $fields[1], 'generation' => $fields[2]],
                    1 => ['type' => 1, 'offset' => $fields[1], 'generation' => $fields[2]],
                    2 => ['type' => 2, 'objectStream' => $fields[1], 'index' => $fields[2], 'generation' => 0],
                    default => throw new \RuntimeException("Unsupported PDF xref entry type {$fields[0]}"),
                };
            }
        }

        return ['entries' => $entries, 'trailer' => $object['dictionary']];
    }

    private function resolveDirectArray(string $raw, string $context): string {
        $raw = trim($raw);
        if (!str_starts_with($raw, '[')) {
            throw new \RuntimeException("{$context} must be a direct array");
        }
        $end = $this->compositeEnd($raw, 0);
        return substr($raw, 0, $end);
    }

    private function nonNegativeInteger(string $raw, string $context): int {
        $raw = trim($raw);
        if (!preg_match('/^\d+$/D', $raw)) {
            throw new \RuntimeException("{$context} is not a non-negative integer");
        }
        $normalized = ltrim($raw, '0');
        $normalized = $normalized === '' ? '0' : $normalized;
        $maximum = (string)PHP_INT_MAX;
        if (strlen($normalized) > strlen($maximum)
            || (strlen($normalized) === strlen($maximum) && strcmp($normalized, $maximum) > 0)) {
            throw new \RuntimeException("{$context} exceeds the supported integer range");
        }
        return (int)$normalized;
    }

    private function unsignedBytes(string $bytes, string $context): int {
        $value = 0;
        for ($index = 0; $index < strlen($bytes); $index++) {
            $byte = ord($bytes[$index]);
            if ($value > intdiv(PHP_INT_MAX - $byte, 256)) {
                throw new \RuntimeException("{$context} exceeds the supported integer range");
            }
            $value = ($value * 256) + $byte;
        }
        return $value;
    }

    private function findFirstPage(string $pdf, array $rootRef): array {
        $stack = [$rootRef];
        $visited = [];

        while ($stack !== []) {
            $ref = array_shift($stack);
            $key = $ref['number'] . ':' . $ref['generation'];
            if (isset($visited[$key])) {
                continue;
            }
            $visited[$key] = true;

            $dictionary = $this->indirectDictionary($pdf, $ref);
            $type = $this->findDictionaryEntry($dictionary, 'Type');
            if ($type !== null && $this->parseName($type['raw'], 'PDF page type') === 'Page') {
                return ['ref' => $ref, 'dictionary' => $dictionary];
            }

            $kids = $this->findDictionaryEntry($dictionary, 'Kids');
            if ($kids === null) {
                continue;
            }
            $kidsArray = $this->resolveArray($pdf, $kids['raw']);
            if (preg_match_all('/(\d+)[ \t\r\n]+(\d+)[ \t\r\n]+R\b/', $kidsArray, $matches, PREG_SET_ORDER)) {
                $children = [];
                foreach ($matches as $match) {
                    $children[] = ['number' => (int)$match[1], 'generation' => (int)$match[2]];
                }
                $stack = array_merge($children, $stack);
            }
        }

        throw new \RuntimeException('PDF Pages tree contains no page');
    }

    private function buildIncrementalRevision(string $pdf, array $state, int $reserve, array $options): array {
        $nextObject = $state['nextObject'];
        $signatureNumber = $nextObject++;
        $widgetNumber = $nextObject++;
        $acroFormNumber = $nextObject++;
        $annotationsNumber = $nextObject++;
        $catalogNumber = $nextObject++;

        $signatureRef = "{$signatureNumber} 0 R";
        $widgetRef = "{$widgetNumber} 0 R";
        $acroFormRef = "{$acroFormNumber} 0 R";
        $annotationsRef = "{$annotationsNumber} 0 R";
        $pageRef = $this->formatReference($state['firstPageRef']);

        $fieldName = $this->textOption($options, 'fieldName', "Signature{$signatureNumber}");
        if ($fieldName === '') {
            throw new \InvalidArgumentException('PDF signature fieldName cannot be empty');
        }

        $signatureLines = [
            '/Type /Sig',
            '/Filter /Adobe.PPKLite',
            '/SubFilter /adbe.pkcs7.detached',
            '/ByteRange ' . self::BYTE_RANGE_PLACEHOLDER,
            '/Contents <' . str_repeat('0', $reserve * 2) . '>',
            '/M ' . $this->pdfTextString($this->pdfDate()),
            '/Name ' . $this->pdfTextString($this->textOption($options, 'name', 'FoxySigningTool')),
        ];
        foreach (['reason' => 'Reason', 'location' => 'Location', 'contact' => 'ContactInfo'] as $option => $pdfKey) {
            $default = $option === 'reason' ? 'Document signed by FoxySigningTool' : '';
            $value = $this->textOption($options, $option, $default);
            if ($value !== '') {
                $signatureLines[] = "/{$pdfKey} " . $this->pdfTextString($value);
            }
        }
        $signatureDictionary = "<<\n" . implode("\n", $signatureLines) . "\n>>";

        $widgetDictionary = "<<\n"
            . "/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/F 132\n/Rect [0 0 0 0]\n"
            . '/T ' . $this->pdfTextString($fieldName) . "\n"
            . "/V {$signatureRef}\n/P {$pageRef}\n>>";

        $acroForm = $this->buildAcroForm($pdf, $state['catalog'], $widgetRef);
        $annotations = $this->buildAnnotations($pdf, $state['firstPage'], $widgetRef);
        $page = $this->setDictionaryValue($state['firstPage'], 'Annots', $annotationsRef);
        $catalog = $this->setDictionaryValue($state['catalog'], 'AcroForm', $acroFormRef);

        $objects = [
            $signatureNumber => ['generation' => 0, 'body' => $signatureDictionary],
            $widgetNumber => ['generation' => 0, 'body' => $widgetDictionary],
            $acroFormNumber => ['generation' => 0, 'body' => $acroForm],
            $annotationsNumber => ['generation' => 0, 'body' => $annotations],
            $catalogNumber => ['generation' => 0, 'body' => $catalog],
            $state['firstPageRef']['number'] => [
                'generation' => $state['firstPageRef']['generation'],
                'body' => $page,
            ],
        ];

        $trailerExtras = [];
        foreach (['Info'] as $key) {
            if (isset($state['trailer'][$key])) {
                $trailerExtras[$key] = $state['trailer'][$key];
            }
        }
        if ($state['updatedId'] !== null) {
            $trailerExtras['ID'] = $state['updatedId'];
        }

        $revision = $this->appendRevision(
            $pdf,
            $objects,
            "{$catalogNumber} 0 R",
            $state['latestXref'],
            max($nextObject, max(array_keys($objects)) + 1),
            $trailerExtras
        );
        return [
            'pdf' => $revision['pdf'],
            'signatureStart' => $revision['offsets'][$signatureNumber],
            'signatureEnd' => $revision['ends'][$signatureNumber],
        ];
    }

    private function buildAcroForm(string $pdf, string $catalog, string $widgetRef): string {
        $entry = $this->findDictionaryEntry($catalog, 'AcroForm');
        if ($entry === null) {
            return "<<\n/SigFlags 3\n/Fields [{$widgetRef}]\n>>";
        }

        $raw = trim($entry['raw']);
        if (str_starts_with($raw, '<<')) {
            $acroForm = $raw;
        } else {
            $acroForm = $this->indirectDictionary($pdf, $this->parseReference($raw, 'PDF AcroForm'));
        }

        $fields = $this->findDictionaryEntry($acroForm, 'Fields');
        $fieldsArray = $fields === null ? '[]' : $this->resolveArray($pdf, $fields['raw']);
        $acroForm = $this->setDictionaryValue($acroForm, 'Fields', $this->appendArrayValue($fieldsArray, $widgetRef));
        return $this->setDictionaryValue($acroForm, 'SigFlags', '3');
    }

    private function buildAnnotations(string $pdf, string $page, string $widgetRef): string {
        $entry = $this->findDictionaryEntry($page, 'Annots');
        $array = $entry === null ? '[]' : $this->resolveArray($pdf, $entry['raw']);
        return $this->appendArrayValue($array, $widgetRef);
    }

    private function appendRevision(
        string $pdf,
        array $objects,
        string $rootRef,
        int $previousXref,
        int $size,
        array $trailerExtras
    ): array {
        if (!str_ends_with($pdf, "\n") && !str_ends_with($pdf, "\r")) {
            $pdf .= "\n";
        }

        ksort($objects, SORT_NUMERIC);
        $revision = '';
        $offsets = [];
        $ends = [];
        foreach ($objects as $number => $object) {
            $offsets[$number] = strlen($pdf) + strlen($revision);
            $revision .= "{$number} {$object['generation']} obj\n{$object['body']}\nendobj\n";
            $ends[$number] = strlen($pdf) + strlen($revision);
        }

        $xrefOffset = strlen($pdf) + strlen($revision);
        $revision .= "xref\n";
        $groups = [];
        foreach (array_keys($objects) as $number) {
            if ($groups === [] || $number !== $groups[array_key_last($groups)]['last'] + 1) {
                $groups[] = ['first' => $number, 'last' => $number];
            } else {
                $groups[array_key_last($groups)]['last'] = $number;
            }
        }
        foreach ($groups as $group) {
            $count = $group['last'] - $group['first'] + 1;
            $revision .= "{$group['first']} {$count}\n";
            for ($number = $group['first']; $number <= $group['last']; $number++) {
                $generation = $objects[$number]['generation'];
                $revision .= sprintf("%010d %05d n \r\n", $offsets[$number], $generation);
            }
        }

        $trailer = "<<\n/Size {$size}\n/Root {$rootRef}\n/Prev {$previousXref}\n";
        foreach ($trailerExtras as $key => $value) {
            $trailer .= "/{$key} {$value}\n";
        }
        $trailer .= '>>';

        return [
            'pdf' => $pdf . $revision
                . "trailer\n{$trailer}\nstartxref\n{$xrefOffset}\n%%EOF\n",
            'offsets' => $offsets,
            'ends' => $ends,
        ];
    }

    private function indirectDictionary(string $pdf, array $ref): string {
        return $this->extractDictionary($this->indirectObjectBody($pdf, $ref));
    }

    private function indirectObjectBody(string $pdf, array $ref): string {
        $cacheKey = $ref['number'] . ':' . $ref['generation'];
        if (isset($this->objectCache[$cacheKey])) {
            return $this->objectCache[$cacheKey];
        }
        $entry = $this->xrefEntries[$ref['number']] ?? null;
        if ($entry === null || $entry['type'] === 0) {
            throw new \RuntimeException("PDF object {$cacheKey} is free or missing");
        }

        if ($entry['type'] === 1) {
            if ($entry['generation'] !== $ref['generation']) {
                throw new \RuntimeException("PDF object {$cacheKey} has a stale generation");
            }
            $object = $this->readIndirectObjectAtOffset($pdf, $entry['offset'], true);
            if ($object['number'] !== $ref['number'] || $object['generation'] !== $ref['generation']) {
                throw new \RuntimeException("PDF xref entry for {$cacheKey} points to another object");
            }
            return $this->objectCache[$cacheKey] = trim($object['value']);
        }

        if ($entry['type'] !== 2 || $ref['generation'] !== 0) {
            throw new \RuntimeException("Unsupported PDF xref entry for object {$cacheKey}");
        }
        return $this->objectCache[$cacheKey] = $this->compressedObjectBody($pdf, $ref['number'], $entry);
    }

    private function readIndirectObjectAtOffset(
        string $pdf,
        int $offset,
        bool $allowIndirectLength
    ): array {
        $position = $this->skipWhitespaceAndComments($pdf, $offset);
        if (!preg_match('/^(\d+)[ \t]+(\d+)[ \t]+obj\b/A', substr($pdf, $position), $header)) {
            throw new \RuntimeException("PDF xref offset {$offset} does not point to an indirect object");
        }
        $number = (int)$header[1];
        $generation = (int)$header[2];
        $position += strlen($header[0]);
        $valueStart = $this->skipWhitespaceAndComments($pdf, $position);
        $valueEnd = $this->valueEnd($pdf, $valueStart);
        $value = substr($pdf, $valueStart, $valueEnd - $valueStart);
        $dictionary = str_starts_with($value, '<<') ? $value : null;
        $position = $this->skipWhitespaceAndComments($pdf, $valueEnd);
        $stream = null;

        if (substr($pdf, $position, 6) === 'stream'
            && $this->isDelimiter($pdf[$position + 6] ?? "\x00")) {
            if ($dictionary === null) {
                throw new \RuntimeException("PDF stream object {$number} has no dictionary");
            }
            $position += 6;
            while (($pdf[$position] ?? '') === ' ' || ($pdf[$position] ?? '') === "\t") {
                $position++;
            }
            if (substr($pdf, $position, 2) === "\r\n") {
                $position += 2;
            } elseif (($pdf[$position] ?? '') === "\r" || ($pdf[$position] ?? '') === "\n") {
                $position++;
            } else {
                throw new \RuntimeException("PDF stream object {$number} has no line break after stream");
            }

            $lengthEntry = $this->findDictionaryEntry($dictionary, 'Length');
            if ($lengthEntry === null) {
                throw new \RuntimeException("PDF stream object {$number} has no Length");
            }
            $lengthRaw = trim($lengthEntry['raw']);
            if (preg_match('/^\d+$/D', $lengthRaw)) {
                $streamLength = $this->nonNegativeInteger($lengthRaw, 'PDF stream length');
            } elseif ($allowIndirectLength) {
                $lengthRef = $this->parseReference($lengthRaw, 'PDF stream Length');
                $streamLength = $this->nonNegativeInteger(
                    $this->indirectObjectBody($pdf, $lengthRef),
                    'PDF stream length object'
                );
            } else {
                throw new \RuntimeException('An xref stream cannot use an unresolved indirect Length');
            }
            if ($streamLength > strlen($pdf) - $position) {
                throw new \RuntimeException("PDF stream object {$number} is truncated");
            }
            $stream = substr($pdf, $position, $streamLength);
            $position += $streamLength;
            $position = $this->skipWhitespaceAndComments($pdf, $position);
            if (substr($pdf, $position, 9) !== 'endstream'
                || !$this->isDelimiter($pdf[$position + 9] ?? "\x00")) {
                throw new \RuntimeException("PDF stream object {$number} has an invalid Length");
            }
            $position += 9;
        }

        $position = $this->skipWhitespaceAndComments($pdf, $position);
        if (substr($pdf, $position, 6) !== 'endobj'
            || !$this->isDelimiter($pdf[$position + 6] ?? "\x00")) {
            throw new \RuntimeException("PDF object {$number} has no endobj marker");
        }

        return [
            'number' => $number,
            'generation' => $generation,
            'value' => $value,
            'dictionary' => $dictionary,
            'stream' => $stream,
        ];
    }

    private function compressedObjectBody(string $pdf, int $objectNumber, array $entry): string {
        $streamNumber = $entry['objectStream'];
        if (!isset($this->objectStreamCache[$streamNumber])) {
            $streamEntry = $this->xrefEntries[$streamNumber] ?? null;
            if ($streamEntry === null || $streamEntry['type'] !== 1) {
                throw new \RuntimeException("PDF object stream {$streamNumber} is missing or compressed");
            }
            $streamObject = $this->readIndirectObjectAtOffset($pdf, $streamEntry['offset'], true);
            if ($streamObject['number'] !== $streamNumber
                || $streamObject['generation'] !== $streamEntry['generation']
                || $streamObject['dictionary'] === null
                || $streamObject['stream'] === null) {
                throw new \RuntimeException("PDF object stream {$streamNumber} is invalid");
            }
            $type = $this->findDictionaryEntry($streamObject['dictionary'], 'Type');
            if ($type === null || $this->parseName($type['raw'], 'PDF object stream type') !== 'ObjStm') {
                throw new \RuntimeException("PDF object {$streamNumber} is not an ObjStm");
            }
            $countEntry = $this->findDictionaryEntry($streamObject['dictionary'], 'N');
            $firstEntry = $this->findDictionaryEntry($streamObject['dictionary'], 'First');
            if ($countEntry === null || $firstEntry === null) {
                throw new \RuntimeException("PDF object stream {$streamNumber} lacks N or First");
            }
            $count = $this->nonNegativeInteger($countEntry['raw'], 'PDF object stream N');
            $first = $this->nonNegativeInteger($firstEntry['raw'], 'PDF object stream First');
            if ($count > 1000000) {
                throw new \RuntimeException("PDF object stream {$streamNumber} is too large");
            }

            $decoded = $this->decodeStream($pdf, $streamObject['stream'], $streamObject['dictionary']);
            if ($first > strlen($decoded)) {
                throw new \RuntimeException("PDF object stream {$streamNumber} has an invalid First offset");
            }
            $header = trim(substr($decoded, 0, $first));
            $tokens = $header === '' ? [] : preg_split('/\s+/', $header);
            if (!is_array($tokens) || count($tokens) !== $count * 2) {
                throw new \RuntimeException("PDF object stream {$streamNumber} has an invalid header");
            }

            $objects = [];
            $order = [];
            for ($index = 0; $index < $count; $index++) {
                $number = $this->nonNegativeInteger($tokens[$index * 2], 'PDF compressed object number');
                $relativeOffset = $this->nonNegativeInteger(
                    $tokens[($index * 2) + 1],
                    'PDF compressed object offset'
                );
                if ($index > 0 && $relativeOffset < $order[$index - 1]['offset']) {
                    throw new \RuntimeException("PDF object stream {$streamNumber} offsets are unsorted");
                }
                $order[] = ['number' => $number, 'offset' => $relativeOffset];
            }
            foreach ($order as $index => $item) {
                $start = $first + $item['offset'];
                $end = isset($order[$index + 1])
                    ? $first + $order[$index + 1]['offset']
                    : strlen($decoded);
                if ($start > $end || $end > strlen($decoded)) {
                    throw new \RuntimeException("PDF object stream {$streamNumber} has invalid object offsets");
                }
                $raw = substr($decoded, $start, $end - $start);
                $valueStart = $this->skipWhitespaceAndComments($raw, 0);
                $valueEnd = $this->valueEnd($raw, $valueStart);
                $objects[$item['number']] = substr($raw, $valueStart, $valueEnd - $valueStart);
            }
            $this->objectStreamCache[$streamNumber] = ['objects' => $objects, 'order' => $order];
        }

        $cached = $this->objectStreamCache[$streamNumber];
        if (!isset($cached['order'][$entry['index']])
            || $cached['order'][$entry['index']]['number'] !== $objectNumber
            || !isset($cached['objects'][$objectNumber])) {
            throw new \RuntimeException("PDF xref has an invalid ObjStm index for object {$objectNumber}");
        }
        return $cached['objects'][$objectNumber];
    }

    private function decodeStream(string $pdf, string $stream, string $dictionary): string {
        $filterEntry = $this->findDictionaryEntry($dictionary, 'Filter');
        if ($filterEntry === null) {
            return $stream;
        }
        $filterRaw = trim($filterEntry['raw']);
        $filters = str_starts_with($filterRaw, '[')
            ? array_map(
                fn(string $value): string => $this->parseName($value, 'PDF stream filter'),
                $this->arrayValues($this->resolveDirectArray($filterRaw, 'PDF Filter'))
            )
            : [$this->parseName($filterRaw, 'PDF stream filter')];

        $params = array_fill(0, count($filters), null);
        $paramsEntry = $this->findDictionaryEntry($dictionary, 'DecodeParms');
        if ($paramsEntry === null) {
            $paramsEntry = $this->findDictionaryEntry($dictionary, 'DP');
        }
        if ($paramsEntry !== null) {
            $paramsRaw = trim($paramsEntry['raw']);
            if (str_starts_with($paramsRaw, '[')) {
                $values = $this->arrayValues($this->resolveDirectArray($paramsRaw, 'PDF DecodeParms'));
                foreach ($values as $index => $value) {
                    if ($index < count($params) && trim($value) !== 'null') {
                        $params[$index] = $this->resolveDictionaryValue($pdf, $value, 'PDF DecodeParms');
                    }
                }
            } elseif ($paramsRaw !== 'null') {
                $params[0] = $this->resolveDictionaryValue($pdf, $paramsRaw, 'PDF DecodeParms');
            }
        }

        $decoded = $stream;
        foreach ($filters as $index => $filter) {
            $decoded = match ($filter) {
                'FlateDecode', 'Fl' => $this->flateDecode($decoded),
                'ASCIIHexDecode', 'AHx' => $this->asciiHexDecode($decoded),
                'ASCII85Decode', 'A85' => $this->ascii85Decode($decoded),
                'RunLengthDecode', 'RL' => $this->runLengthDecode($decoded),
                default => throw new \RuntimeException("Unsupported PDF stream filter: {$filter}"),
            };
            if ($params[$index] !== null) {
                $decoded = $this->applyPredictor($decoded, $params[$index]);
            }
        }
        return $decoded;
    }

    private function flateDecode(string $data): string {
        $decoded = @gzuncompress($data);
        if ($decoded === false) {
            $decoded = @zlib_decode($data);
        }
        if ($decoded === false) {
            throw new \RuntimeException('Unable to decode PDF Flate stream');
        }
        return $decoded;
    }

    private function asciiHexDecode(string $data): string {
        $end = strpos($data, '>');
        if ($end === false) {
            throw new \RuntimeException('PDF ASCIIHex stream has no end marker');
        }
        $hex = preg_replace('/[\x00\x09\x0A\x0C\x0D\x20]/', '', substr($data, 0, $end));
        if ($hex === null || preg_match('/^[0-9A-Fa-f]*$/D', $hex) !== 1) {
            throw new \RuntimeException('PDF ASCIIHex stream contains invalid data');
        }
        if (strlen($hex) % 2 !== 0) {
            $hex .= '0';
        }
        $decoded = hex2bin($hex);
        if ($decoded === false) {
            throw new \RuntimeException('Unable to decode PDF ASCIIHex stream');
        }
        return $decoded;
    }

    private function ascii85Decode(string $data): string {
        $data = preg_replace('/[\x00\x09\x0A\x0C\x0D\x20]/', '', $data);
        if ($data === null) {
            throw new \RuntimeException('Unable to normalize PDF ASCII85 stream');
        }
        if (str_starts_with($data, '<~')) {
            $data = substr($data, 2);
        }
        $end = strpos($data, '~>');
        if ($end === false) {
            throw new \RuntimeException('PDF ASCII85 stream has no end marker');
        }
        $data = substr($data, 0, $end);
        $decoded = '';
        $group = [];
        for ($index = 0; $index < strlen($data); $index++) {
            $character = $data[$index];
            if ($character === 'z') {
                if ($group !== []) {
                    throw new \RuntimeException('Invalid z inside a PDF ASCII85 group');
                }
                $decoded .= "\x00\x00\x00\x00";
                continue;
            }
            $value = ord($character) - 33;
            if ($value < 0 || $value > 84) {
                throw new \RuntimeException('PDF ASCII85 stream contains an invalid character');
            }
            $group[] = $value;
            if (count($group) === 5) {
                $number = 0;
                foreach ($group as $digit) {
                    $number = ($number * 85) + $digit;
                }
                if ($number > 0xffffffff) {
                    throw new \RuntimeException('PDF ASCII85 group overflows 32 bits');
                }
                $decoded .= pack('N', $number);
                $group = [];
            }
        }
        if (count($group) === 1) {
            throw new \RuntimeException('PDF ASCII85 stream has an invalid final group');
        }
        if ($group !== []) {
            $outputBytes = count($group) - 1;
            while (count($group) < 5) {
                $group[] = 84;
            }
            $number = 0;
            foreach ($group as $digit) {
                $number = ($number * 85) + $digit;
            }
            if ($number > 0xffffffff) {
                throw new \RuntimeException('PDF ASCII85 group overflows 32 bits');
            }
            $decoded .= substr(pack('N', $number), 0, $outputBytes);
        }
        return $decoded;
    }

    private function runLengthDecode(string $data): string {
        $decoded = '';
        $position = 0;
        $length = strlen($data);
        while ($position < $length) {
            $control = ord($data[$position++]);
            if ($control === 128) {
                return $decoded;
            }
            if ($control <= 127) {
                $count = $control + 1;
                if ($position + $count > $length) {
                    throw new \RuntimeException('PDF RunLength stream is truncated');
                }
                $decoded .= substr($data, $position, $count);
                $position += $count;
                continue;
            }
            if ($position >= $length) {
                throw new \RuntimeException('PDF RunLength stream is truncated');
            }
            $decoded .= str_repeat($data[$position++], 257 - $control);
        }
        throw new \RuntimeException('PDF RunLength stream has no end marker');
    }

    private function applyPredictor(string $data, string $parameters): string {
        $predictor = $this->dictionaryInteger($parameters, 'Predictor', 1);
        if ($predictor <= 1) {
            return $data;
        }
        $colors = $this->dictionaryInteger($parameters, 'Colors', 1);
        $bits = $this->dictionaryInteger($parameters, 'BitsPerComponent', 8);
        $columns = $this->dictionaryInteger($parameters, 'Columns', 1);
        if ($colors < 1 || $columns < 1 || $bits !== 8) {
            throw new \RuntimeException('Unsupported PDF predictor parameters');
        }
        $rowBytes = $colors * $columns;
        $bytesPerPixel = $colors;

        if ($predictor === 2) {
            if (strlen($data) % $rowBytes !== 0) {
                throw new \RuntimeException('PDF TIFF predictor data is truncated');
            }
            $decoded = '';
            for ($rowStart = 0; $rowStart < strlen($data); $rowStart += $rowBytes) {
                $row = substr($data, $rowStart, $rowBytes);
                for ($index = $bytesPerPixel; $index < $rowBytes; $index++) {
                    $row[$index] = chr((ord($row[$index]) + ord($row[$index - $bytesPerPixel])) & 0xff);
                }
                $decoded .= $row;
            }
            return $decoded;
        }
        if ($predictor < 10 || $predictor > 15) {
            throw new \RuntimeException("Unsupported PDF predictor {$predictor}");
        }

        $encodedRowBytes = $rowBytes + 1;
        if (strlen($data) % $encodedRowBytes !== 0) {
            throw new \RuntimeException('PDF PNG predictor data is truncated');
        }
        $decoded = '';
        $previous = str_repeat("\x00", $rowBytes);
        for ($rowStart = 0; $rowStart < strlen($data); $rowStart += $encodedRowBytes) {
            $filter = ord($data[$rowStart]);
            if ($filter > 4) {
                throw new \RuntimeException("Unsupported PDF PNG predictor filter {$filter}");
            }
            $row = substr($data, $rowStart + 1, $rowBytes);
            for ($index = 0; $index < $rowBytes; $index++) {
                $left = $index >= $bytesPerPixel ? ord($row[$index - $bytesPerPixel]) : 0;
                $up = ord($previous[$index]);
                $upperLeft = $index >= $bytesPerPixel ? ord($previous[$index - $bytesPerPixel]) : 0;
                $prediction = match ($filter) {
                    0 => 0,
                    1 => $left,
                    2 => $up,
                    3 => intdiv($left + $up, 2),
                    4 => $this->paeth($left, $up, $upperLeft),
                };
                $row[$index] = chr((ord($row[$index]) + $prediction) & 0xff);
            }
            $decoded .= $row;
            $previous = $row;
        }
        return $decoded;
    }

    private function dictionaryInteger(string $dictionary, string $key, int $default): int {
        $entry = $this->findDictionaryEntry($dictionary, $key);
        return $entry === null ? $default : $this->nonNegativeInteger($entry['raw'], "PDF {$key}");
    }

    private function paeth(int $left, int $up, int $upperLeft): int {
        $estimate = $left + $up - $upperLeft;
        $leftDistance = abs($estimate - $left);
        $upDistance = abs($estimate - $up);
        $upperLeftDistance = abs($estimate - $upperLeft);
        if ($leftDistance <= $upDistance && $leftDistance <= $upperLeftDistance) {
            return $left;
        }
        return $upDistance <= $upperLeftDistance ? $up : $upperLeft;
    }

    private function extractDictionary(string $source): string {
        $start = strpos($source, '<<');
        if ($start === false) {
            throw new \RuntimeException('Expected a PDF dictionary');
        }
        $end = $this->compositeEnd($source, $start);
        return substr($source, $start, $end - $start);
    }

    private function resolveArray(string $pdf, string $raw): string {
        $raw = trim($raw);
        if (str_starts_with($raw, '[')) {
            $end = $this->compositeEnd($raw, 0);
            return substr($raw, 0, $end);
        }

        $body = trim($this->indirectObjectBody($pdf, $this->parseReference($raw, 'PDF array')));
        $start = strpos($body, '[');
        if ($start === false) {
            throw new \RuntimeException('Referenced PDF object is not an array');
        }
        $end = $this->compositeEnd($body, $start);
        return substr($body, $start, $end - $start);
    }

    private function appendArrayValue(string $array, string $value): string {
        $end = $this->compositeEnd($array, 0);
        return substr($array, 0, $end - 1) . " {$value} ]";
    }

    private function findDictionaryEntry(string $dictionary, string $key): ?array {
        $start = strpos($dictionary, '<<');
        if ($start === false) {
            throw new \RuntimeException('Expected a PDF dictionary');
        }

        $position = $start + 2;
        $length = strlen($dictionary);
        while ($position < $length) {
            $position = $this->skipWhitespaceAndComments($dictionary, $position);
            if (substr($dictionary, $position, 2) === '>>') {
                return null;
            }
            if (($dictionary[$position] ?? '') !== '/') {
                throw new \RuntimeException('Malformed PDF dictionary key');
            }

            $nameEnd = $this->nameEnd($dictionary, $position);
            $name = $this->decodeName(substr($dictionary, $position + 1, $nameEnd - $position - 1));
            $valueStart = $this->skipWhitespaceAndComments($dictionary, $nameEnd);
            $valueEnd = $this->valueEnd($dictionary, $valueStart);
            if ($name === $key) {
                return [
                    'start' => $valueStart,
                    'end' => $valueEnd,
                    'raw' => substr($dictionary, $valueStart, $valueEnd - $valueStart),
                ];
            }
            $position = $valueEnd;
        }

        throw new \RuntimeException('Unterminated PDF dictionary');
    }

    private function setDictionaryValue(string $dictionary, string $key, string $value): string {
        $entry = $this->findDictionaryEntry($dictionary, $key);
        if ($entry !== null) {
            return substr_replace($dictionary, $value, $entry['start'], $entry['end'] - $entry['start']);
        }

        $start = strpos($dictionary, '<<');
        $end = $this->compositeEnd($dictionary, $start);
        $closing = $end - 2;
        return substr($dictionary, 0, $closing) . "\n/{$key} {$value}\n" . substr($dictionary, $closing);
    }

    private function valueEnd(string $source, int $position): int {
        if (substr($source, $position, 2) === '<<' || ($source[$position] ?? '') === '[') {
            return $this->compositeEnd($source, $position);
        }
        if (($source[$position] ?? '') === '(') {
            return $this->literalStringEnd($source, $position);
        }
        if (($source[$position] ?? '') === '<') {
            $end = strpos($source, '>', $position + 1);
            if ($end === false) {
                throw new \RuntimeException('Unterminated PDF hexadecimal string');
            }
            return $end + 1;
        }
        if (($source[$position] ?? '') === '/') {
            return $this->nameEnd($source, $position);
        }

        $firstEnd = $this->tokenEnd($source, $position);
        $first = substr($source, $position, $firstEnd - $position);
        if (preg_match('/^[+-]?\d+$/', $first)) {
            $secondStart = $this->skipWhitespaceAndComments($source, $firstEnd);
            $secondEnd = $this->tokenEnd($source, $secondStart);
            $second = substr($source, $secondStart, $secondEnd - $secondStart);
            if (preg_match('/^\d+$/', $second)) {
                $rStart = $this->skipWhitespaceAndComments($source, $secondEnd);
                $rEnd = $this->tokenEnd($source, $rStart);
                if (substr($source, $rStart, $rEnd - $rStart) === 'R') {
                    return $rEnd;
                }
            }
        }

        return $firstEnd;
    }

    private function compositeEnd(string $source, int $position): int {
        $stack = [];
        if (substr($source, $position, 2) === '<<') {
            $stack[] = '>>';
            $position += 2;
        } elseif (($source[$position] ?? '') === '[') {
            $stack[] = ']';
            $position++;
        } else {
            throw new \RuntimeException('Expected a PDF composite value');
        }

        $length = strlen($source);
        while ($position < $length && $stack !== []) {
            if (($source[$position] ?? '') === '%') {
                $position = $this->commentEnd($source, $position);
                continue;
            }
            if (($source[$position] ?? '') === '(') {
                $position = $this->literalStringEnd($source, $position);
                continue;
            }
            if (substr($source, $position, 2) === '<<') {
                $stack[] = '>>';
                $position += 2;
                continue;
            }
            if (substr($source, $position, 2) === '>>' && end($stack) === '>>') {
                array_pop($stack);
                $position += 2;
                continue;
            }
            if (($source[$position] ?? '') === '[') {
                $stack[] = ']';
                $position++;
                continue;
            }
            if (($source[$position] ?? '') === ']' && end($stack) === ']') {
                array_pop($stack);
                $position++;
                continue;
            }
            if (($source[$position] ?? '') === '<') {
                $end = strpos($source, '>', $position + 1);
                if ($end === false) {
                    throw new \RuntimeException('Unterminated PDF hexadecimal string');
                }
                $position = $end + 1;
                continue;
            }
            $position++;
        }

        if ($stack !== []) {
            throw new \RuntimeException('Unterminated PDF composite value');
        }
        return $position;
    }

    private function literalStringEnd(string $source, int $position): int {
        $depth = 1;
        $position++;
        $length = strlen($source);
        while ($position < $length) {
            $character = $source[$position];
            if ($character === '\\') {
                $position += 2;
                continue;
            }
            if ($character === '(') {
                $depth++;
            } elseif ($character === ')') {
                $depth--;
                if ($depth === 0) {
                    return $position + 1;
                }
            }
            $position++;
        }
        throw new \RuntimeException('Unterminated PDF literal string');
    }

    private function nameEnd(string $source, int $position): int {
        $position++;
        $length = strlen($source);
        while ($position < $length && !$this->isDelimiter($source[$position])) {
            $position++;
        }
        return $position;
    }

    private function tokenEnd(string $source, int $position): int {
        $length = strlen($source);
        while ($position < $length && !$this->isDelimiter($source[$position])) {
            $position++;
        }
        return $position;
    }

    private function skipWhitespaceAndComments(string $source, int $position): int {
        $length = strlen($source);
        while ($position < $length) {
            if (str_contains("\x00\x09\x0A\x0C\x0D\x20", $source[$position])) {
                $position++;
                continue;
            }
            if ($source[$position] === '%') {
                $position = $this->commentEnd($source, $position);
                continue;
            }
            break;
        }
        return $position;
    }

    private function commentEnd(string $source, int $position): int {
        $length = strlen($source);
        while ($position < $length && $source[$position] !== "\r" && $source[$position] !== "\n") {
            $position++;
        }
        return $position;
    }

    private function isDelimiter(string $character): bool {
        return str_contains("\x00\x09\x0A\x0C\x0D\x20()<>[]{}/%", $character);
    }

    private function parseReference(string $raw, string $context): array {
        if (!preg_match('/^(\d+)[ \t\r\n]+(\d+)[ \t\r\n]+R$/', trim($raw), $match)) {
            throw new \RuntimeException("{$context} is not an indirect reference");
        }
        return ['number' => (int)$match[1], 'generation' => (int)$match[2]];
    }

    private function parseName(string $raw, string $context): string {
        $raw = trim($raw);
        if (!str_starts_with($raw, '/')) {
            throw new \RuntimeException("{$context} is not a PDF name");
        }
        return $this->decodeName(substr($raw, 1));
    }

    private function decodeName(string $name): string {
        $decoded = '';
        $length = strlen($name);
        for ($index = 0; $index < $length; $index++) {
            if ($name[$index] !== '#') {
                $decoded .= $name[$index];
                continue;
            }
            if ($index + 2 >= $length
                || !ctype_xdigit($name[$index + 1])
                || !ctype_xdigit($name[$index + 2])) {
                throw new \RuntimeException('Malformed escape in PDF name');
            }
            $decoded .= chr((int)hexdec(substr($name, $index + 1, 2)));
            $index += 2;
        }
        return $decoded;
    }

    private function formatReference(array $ref): string {
        return "{$ref['number']} {$ref['generation']} R";
    }

    private function pdfTextString(string $value): string {
        if (!mb_check_encoding($value, 'UTF-8')) {
            throw new \InvalidArgumentException('PDF signature text must be valid UTF-8');
        }
        if (preg_match('/[^\x20-\x7E]/', $value)) {
            return '<FEFF' . strtoupper(bin2hex(mb_convert_encoding($value, 'UTF-16BE', 'UTF-8'))) . '>';
        }

        return '(' . strtr($value, [
            '\\' => '\\\\',
            '(' => '\\(',
            ')' => '\\)',
        ]) . ')';
    }

    private function pdfDate(): string {
        $offset = date('O');
        return 'D:' . date('YmdHis') . substr($offset, 0, 3) . "'" . substr($offset, 3, 2) . "'";
    }
}
