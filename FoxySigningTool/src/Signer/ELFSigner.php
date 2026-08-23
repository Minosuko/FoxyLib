<?php
declare(strict_types=1);
namespace FoxySigningTool\Signer;

use FoxyCryptLib\{PEM, RSA, X509Certificate};
use FoxySigningTool\PKCS7;

final class ELFSigner {
    public const NOTE_SECTION = '.note.foxy.cms';
    public const NOTE_OWNER = "FOXY\x00";
    public const NOTE_TYPE = 1;
    public const DESCRIPTOR_MAGIC = 'FXE1';

    private const ELFCLASS32 = 1;
    private const ELFCLASS64 = 2;
    private const ELFDATA2LSB = 1;
    private const ELFDATA2MSB = 2;
    private const SHT_STRTAB = 3;
    private const SHT_NOTE = 7;
    private const SHT_NOBITS = 8;
    private const PT_LOAD = 1;
    private const PN_XNUM = 0xffff;
    private const SHN_LORESERVE = 0xff00;
    private const SHN_XINDEX = 0xffff;

    private RSA $signerKey;
    private string $certPem;
    private array $extraCerts;
    private ?array $timestamp;

    public function __construct(
        object $signerKey,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = [],
        ?array $timestamp = null
    ) {
        if (!$signerKey instanceof RSA) {
            throw new \InvalidArgumentException('ELF signing requires an RSA private key');
        }
        if (strtolower($hashAlgo) !== 'sha256') {
            throw new \InvalidArgumentException('ELF signing currently supports SHA-256 only');
        }

        try {
            $certificate = X509Certificate::fromPEM($certPem);
            $certificateKey = RSA::fromPEM(PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY'));
        } catch (\Throwable $exception) {
            throw new \InvalidArgumentException('ELF signing requires an RSA certificate', 0, $exception);
        }
        $privatePublic = $signerKey->getPublicKey();
        $certificatePublic = $certificateKey->getPublicKey();
        if (!$privatePublic['n']->equals($certificatePublic['n'])
            || !$privatePublic['e']->equals($certificatePublic['e'])) {
            throw new \InvalidArgumentException('ELF signing key does not match the certificate');
        }
        foreach ($extraCerts as $extraCert) {
            if (!is_string($extraCert)) {
                throw new \InvalidArgumentException('Each extra certificate must be PEM encoded');
            }
            X509Certificate::fromPEM($extraCert);
        }

        $this->signerKey = $signerKey;
        $this->certPem = $certPem;
        $this->extraCerts = $extraCerts;
        $this->timestamp = $timestamp;
    }

    public static function fromPKCS12(string $pkcs12Path, string $password, string $hashAlgo = 'sha256'): self {
        $contents = @file_get_contents($pkcs12Path);
        if ($contents === false) {
            throw new \RuntimeException("Unable to read PKCS12 file: {$pkcs12Path}");
        }
        $pkcs12 = \FoxyCryptLib\FoxyCryptLib::pkcs12Decode($contents, $password);
        $keyInfo = $pkcs12['privateKeys'][0] ?? throw new \RuntimeException('No private key in PKCS12');
        $signerKey = PESigner::keyInfoToKey($keyInfo);
        if (!$signerKey instanceof RSA) {
            throw new \RuntimeException('ELF signing requires an RSA key in PKCS12');
        }

        $public = $signerKey->getPublicKey();
        $signerCertificate = null;
        $extraCerts = [];
        foreach ($pkcs12['certificates'] ?? [] as $certificateDer) {
            $certificatePem = PEM::encode($certificateDer, 'CERTIFICATE');
            try {
                $certificate = X509Certificate::fromDER($certificateDer);
                $certificateKey = RSA::fromPEM(
                    PEM::encode($certificate['subjectPublicKeyInfo']['raw'], 'PUBLIC KEY')
                );
                $candidate = $certificateKey->getPublicKey();
                $matches = $public['n']->equals($candidate['n']) && $public['e']->equals($candidate['e']);
            } catch (\Throwable) {
                $matches = false;
            }
            if ($signerCertificate === null && $matches) {
                $signerCertificate = $certificatePem;
            } else {
                $extraCerts[] = $certificatePem;
            }
        }
        if ($signerCertificate === null) {
            throw new \RuntimeException('No certificate in PKCS12 matches the private key');
        }
        return new self($signerKey, $signerCertificate, $hashAlgo, $extraCerts);
    }

    public static function fromPEM(
        string $keyPem,
        string $certPem,
        string $hashAlgo = 'sha256',
        array $extraCerts = []
    ): self {
        return new self(PESigner::loadKeyFromPEM($keyPem), $certPem, $hashAlgo, $extraCerts);
    }

    public function signFile(string $inputPath, ?string $outputPath = null, bool $embedded = true): string {
        $elfData = @file_get_contents($inputPath);
        if ($elfData === false) {
            throw new \RuntimeException("Unable to read ELF file: {$inputPath}");
        }
        $outputPath ??= $inputPath;
        $permissions = @fileperms($inputPath);
        // A temporary replacement inode cannot safely inherit setuid/setgid ownership semantics.
        $mode = $permissions === false ? null : ($permissions & 0777);

        if ($embedded) {
            $this->writeFileSafely($outputPath, $this->signEmbeddedBinary($elfData), $mode);
        } else {
            if ($outputPath !== $inputPath) {
                $this->writeFileSafely($outputPath, $elfData, $mode);
            }
            $this->writeFileSafely($outputPath . '.sig', $this->signDetached($elfData), null);
        }
        return $outputPath;
    }

    public function signDetached(string $elfData): string {
        $this->parseELF($elfData);
        return PKCS7::buildDetachedSignature(
            $elfData,
            $this->signerKey,
            $this->certPem,
            'sha256',
            $this->extraCerts,
            $this->timestamp
        );
    }

    public function signEmbeddedBinary(string $elfData): string {
        $elf = $this->parseELF($elfData);
        $descriptorPrefix = $this->buildDescriptorPrefix($elfData, $elf);
        $cms = PKCS7::buildDetachedSignature(
            $descriptorPrefix . $elfData,
            $this->signerKey,
            $this->certPem,
            'sha256',
            $this->extraCerts,
            $this->timestamp
        );
        return $this->embedSignature($elfData, $elf, $descriptorPrefix . $cms);
    }

    private function parseELF(string $data): array {
        if (strlen($data) < 16 || substr($data, 0, 4) !== "\x7fELF") {
            throw new \RuntimeException('Not an ELF file');
        }
        $class = ord($data[4]);
        $encoding = ord($data[5]);
        if (!in_array($class, [self::ELFCLASS32, self::ELFCLASS64], true)) {
            throw new \RuntimeException("Unsupported ELF class: {$class}");
        }
        if (!in_array($encoding, [self::ELFDATA2LSB, self::ELFDATA2MSB], true)) {
            throw new \RuntimeException("Unsupported ELF data encoding: {$encoding}");
        }
        if (ord($data[6]) !== 1) {
            throw new \RuntimeException('Unsupported ELF identification version');
        }
        if ($class === self::ELFCLASS64 && PHP_INT_SIZE < 8) {
            throw new \RuntimeException('ELF64 signing requires 64-bit PHP');
        }

        $littleEndian = $encoding === self::ELFDATA2LSB;
        $headerSize = $class === self::ELFCLASS64 ? 64 : 52;
        $sectionHeaderSize = $class === self::ELFCLASS64 ? 64 : 40;
        if (strlen($data) < $headerSize) {
            throw new \RuntimeException('ELF header is truncated');
        }

        $programOffsetField = $class === self::ELFCLASS64 ? 0x20 : 0x1c;
        $programEntrySizeField = $class === self::ELFCLASS64 ? 0x36 : 0x2a;
        $programCountField = $class === self::ELFCLASS64 ? 0x38 : 0x2c;
        $sectionOffsetField = $class === self::ELFCLASS64 ? 0x28 : 0x20;
        $sectionEntrySizeField = $class === self::ELFCLASS64 ? 0x3a : 0x2e;
        $sectionCountField = $class === self::ELFCLASS64 ? 0x3c : 0x30;
        $sectionStringIndexField = $class === self::ELFCLASS64 ? 0x3e : 0x32;
        $programTableOffset = $this->readUInt(
            $data,
            $programOffsetField,
            $class === self::ELFCLASS64 ? 8 : 4,
            $littleEndian
        );
        $programEntrySize = $this->readUInt($data, $programEntrySizeField, 2, $littleEndian);
        $rawProgramCount = $this->readUInt($data, $programCountField, 2, $littleEndian);
        $sectionTableOffset = $this->readUInt(
            $data,
            $sectionOffsetField,
            $class === self::ELFCLASS64 ? 8 : 4,
            $littleEndian
        );
        $entrySize = $this->readUInt($data, $sectionEntrySizeField, 2, $littleEndian);
        $rawSectionCount = $this->readUInt($data, $sectionCountField, 2, $littleEndian);
        $rawStringIndex = $this->readUInt($data, $sectionStringIndexField, 2, $littleEndian);

        if ($sectionTableOffset === 0 || $entrySize === 0) {
            throw new \RuntimeException('ELF files without a section table are not supported');
        }
        if ($entrySize !== $sectionHeaderSize) {
            throw new \RuntimeException("Unsupported ELF section-header size: {$entrySize}");
        }
        $this->assertFileRange(strlen($data), $sectionTableOffset, $entrySize, 'ELF section table');

        $sectionZeroRaw = substr($data, $sectionTableOffset, $entrySize);
        $sectionZero = $this->parseSectionZero($sectionZeroRaw, $class, $littleEndian);
        $sectionCount = $rawSectionCount === 0 ? $sectionZero['size'] : $rawSectionCount;
        $sectionStringIndex = $rawStringIndex === self::SHN_XINDEX
            ? $sectionZero['link']
            : $rawStringIndex;
        if ($sectionCount < 1 || $sectionCount > 65535) {
            throw new \RuntimeException('ELF section count is invalid or too large');
        }
        $this->assertFileRange(
            strlen($data),
            $sectionTableOffset,
            $sectionCount * $entrySize,
            'ELF section table'
        );
        if ($sectionStringIndex < 1 || $sectionStringIndex >= $sectionCount) {
            throw new \RuntimeException('ELF section-name string-table index is invalid');
        }

        $programCount = $rawProgramCount === self::PN_XNUM ? $sectionZero['info'] : $rawProgramCount;
        if ($programCount > 1000000) {
            throw new \RuntimeException('ELF program-header count is too large');
        }
        if ($programCount > 0) {
            $expectedProgramEntrySize = $class === self::ELFCLASS64 ? 56 : 32;
            if ($programEntrySize !== $expectedProgramEntrySize) {
                throw new \RuntimeException("Unsupported ELF program-header size: {$programEntrySize}");
            }
            $this->assertFileRange(
                strlen($data),
                $programTableOffset,
                $programCount * $programEntrySize,
                'ELF program-header table'
            );
            for ($index = 0; $index < $programCount; $index++) {
                $programRaw = substr(
                    $data,
                    $programTableOffset + ($index * $programEntrySize),
                    $programEntrySize
                );
                if ($this->readUInt($programRaw, 0, 4, $littleEndian) === 0) {
                    continue;
                }
                $program = $this->parseProgramHeader(
                    $programRaw,
                    $class,
                    $littleEndian
                );
                if ($program['fileSize'] > 0) {
                    $this->assertFileRange(
                        strlen($data),
                        $program['offset'],
                        $program['fileSize'],
                        "ELF program segment {$index}"
                    );
                }
                if ($program['type'] === self::PT_LOAD && $program['fileSize'] > $program['memorySize']) {
                    throw new \RuntimeException("ELF load segment {$index} has p_filesz greater than p_memsz");
                }
            }
        } elseif ($programTableOffset !== 0 && $programEntrySize !== 0) {
            // A zero-count table is ignored by the loader, but its metadata must still be representable.
            $this->assertFileRange(strlen($data), $programTableOffset, 0, 'ELF program-header table');
        }

        $sectionTable = substr($data, $sectionTableOffset, $sectionCount * $entrySize);
        $stringSectionRaw = substr($sectionTable, $sectionStringIndex * $entrySize, $entrySize);
        $stringSection = $this->parseSectionHeader($stringSectionRaw, $class, $littleEndian);
        if ($stringSection['type'] !== self::SHT_STRTAB) {
            throw new \RuntimeException('ELF section-name table is not SHT_STRTAB');
        }
        $this->assertFileRange(
            strlen($data),
            $stringSection['offset'],
            $stringSection['size'],
            'ELF section-name string table'
        );
        $sectionNames = substr($data, $stringSection['offset'], $stringSection['size']);
        if ($sectionNames === '' || $sectionNames[0] !== "\x00" || !str_ends_with($sectionNames, "\x00")) {
            throw new \RuntimeException('ELF section-name string table is malformed');
        }

        for ($index = 0; $index < $sectionCount; $index++) {
            $sectionRaw = substr($sectionTable, $index * $entrySize, $entrySize);
            if ($this->readUInt($sectionRaw, 0x04, 4, $littleEndian) === 0) {
                continue;
            }
            $section = $this->parseSectionHeader($sectionRaw, $class, $littleEndian);
            if ($section['type'] !== self::SHT_NOBITS && $section['size'] > 0) {
                $this->assertFileRange(
                    strlen($data),
                    $section['offset'],
                    $section['size'],
                    "ELF section {$index}"
                );
            }
            if ($section['name'] < 0 || $section['name'] >= strlen($sectionNames)) {
                throw new \RuntimeException("ELF section {$index} name offset is outside the string table");
            }
            if ($this->sectionNameEquals($sectionNames, $section['name'], self::NOTE_SECTION)) {
                throw new \RuntimeException('ELF already contains a Foxy CMS signature section');
            }
            if ($section['type'] === self::SHT_NOTE && $section['size'] > 0) {
                $this->assertFileRange(
                    strlen($data),
                    $section['offset'],
                    $section['size'],
                    "ELF note section {$index}"
                );
                if ($this->containsFoxyNote(
                    substr($data, $section['offset'], $section['size']),
                    $littleEndian,
                    $this->noteAlignment($class, $section['alignment'])
                )) {
                    throw new \RuntimeException('ELF already contains a Foxy CMS signature note');
                }
            }
        }

        return [
            'class' => $class,
            'encoding' => $encoding,
            'littleEndian' => $littleEndian,
            'headerSize' => $headerSize,
            'sectionHeaderSize' => $sectionHeaderSize,
            'sectionOffsetField' => $sectionOffsetField,
            'sectionCountField' => $sectionCountField,
            'sectionStringIndexField' => $sectionStringIndexField,
            'rawSectionCount' => $rawSectionCount,
            'rawStringIndex' => $rawStringIndex,
            'sectionTableOffset' => $sectionTableOffset,
            'sectionCount' => $sectionCount,
            'sectionStringIndex' => $sectionStringIndex,
            'sectionTable' => $sectionTable,
            'sectionNames' => $sectionNames,
        ];
    }

    private function buildDescriptorPrefix(string $data, array $elf): string {
        $offsetWidth = $elf['class'] === self::ELFCLASS64 ? 8 : 4;
        return self::DESCRIPTOR_MAGIC
            . chr($elf['class'])
            . chr($elf['encoding'])
            . "\x00\x00"
            . pack('J', strlen($data))
            . substr($data, $elf['sectionOffsetField'], $offsetWidth)
            . substr($data, $elf['sectionCountField'], 2)
            . substr($data, $elf['sectionStringIndexField'], 2);
    }

    private function embedSignature(string $data, array $elf, string $descriptor): string {
        $noteAlignment = $elf['class'] === self::ELFCLASS64 ? 8 : 4;
        $note = $this->buildNote($descriptor, $elf['littleEndian'], $noteAlignment);
        $noteOffset = $this->align(strlen($data), $noteAlignment);
        $newStringOffset = $noteOffset + strlen($note);
        $nameOffset = strlen($elf['sectionNames']);
        $newStringTable = $elf['sectionNames'] . self::NOTE_SECTION . "\x00";
        $tableAlignment = $elf['class'] === self::ELFCLASS64 ? 8 : 4;
        $newSectionTableOffset = $this->align(
            $newStringOffset + strlen($newStringTable),
            $tableAlignment
        );
        $newSectionCount = $elf['sectionCount'] + 1;

        $table = $elf['sectionTable'];
        $stringHeaderOffset = $elf['sectionStringIndex'] * $elf['sectionHeaderSize'];
        $stringHeader = $this->updateSectionRange(
            substr($table, $stringHeaderOffset, $elf['sectionHeaderSize']),
            $elf['class'],
            $elf['littleEndian'],
            $newStringOffset,
            strlen($newStringTable)
        );
        $table = substr_replace(
            $table,
            $stringHeader,
            $stringHeaderOffset,
            $elf['sectionHeaderSize']
        );
        $sectionZero = $this->updateExtendedSectionNumbering(
            substr($table, 0, $elf['sectionHeaderSize']),
            $elf['class'],
            $elf['littleEndian'],
            $newSectionCount,
            $elf['sectionStringIndex']
        );
        $table = substr_replace($table, $sectionZero, 0, $elf['sectionHeaderSize']);
        $table .= $this->buildNoteSectionHeader(
            $elf['class'],
            $elf['littleEndian'],
            $nameOffset,
            $noteOffset,
            strlen($note),
            $noteAlignment
        );

        $output = $data . str_repeat("\x00", $noteOffset - strlen($data)) . $note . $newStringTable;
        $output .= str_repeat("\x00", $newSectionTableOffset - strlen($output));
        $output .= $table;

        $offsetWidth = $elf['class'] === self::ELFCLASS64 ? 8 : 4;
        $output = substr_replace(
            $output,
            $this->writeUInt($newSectionTableOffset, $offsetWidth, $elf['littleEndian']),
            $elf['sectionOffsetField'],
            $offsetWidth
        );
        $headerSectionCount = $newSectionCount >= self::SHN_LORESERVE ? 0 : $newSectionCount;
        $headerStringIndex = $elf['sectionStringIndex'] >= self::SHN_LORESERVE
            ? self::SHN_XINDEX
            : $elf['sectionStringIndex'];
        $output = substr_replace(
            $output,
            $this->writeUInt($headerSectionCount, 2, $elf['littleEndian']),
            $elf['sectionCountField'],
            2
        );
        return substr_replace(
            $output,
            $this->writeUInt($headerStringIndex, 2, $elf['littleEndian']),
            $elf['sectionStringIndexField'],
            2
        );
    }

    private function buildNote(string $descriptor, bool $littleEndian, int $alignment): string {
        $owner = self::NOTE_OWNER;
        $header = $this->writeUInt(strlen($owner), 4, $littleEndian)
            . $this->writeUInt(strlen($descriptor), 4, $littleEndian)
            . $this->writeUInt(self::NOTE_TYPE, 4, $littleEndian);
        $descriptionOffset = $this->align(strlen($header) + strlen($owner), $alignment);
        $note = $header . $owner . str_repeat(
            "\x00",
            $descriptionOffset - strlen($header) - strlen($owner)
        ) . $descriptor;
        return $note . str_repeat("\x00", $this->align(strlen($note), $alignment) - strlen($note));
    }

    private function buildNoteSectionHeader(
        int $class,
        bool $littleEndian,
        int $nameOffset,
        int $noteOffset,
        int $noteSize,
        int $noteAlignment
    ): string {
        if ($class === self::ELFCLASS64) {
            return $this->writeUInt($nameOffset, 4, $littleEndian)
                . $this->writeUInt(self::SHT_NOTE, 4, $littleEndian)
                . $this->writeUInt(0, 8, $littleEndian)
                . $this->writeUInt(0, 8, $littleEndian)
                . $this->writeUInt($noteOffset, 8, $littleEndian)
                . $this->writeUInt($noteSize, 8, $littleEndian)
                . $this->writeUInt(0, 4, $littleEndian)
                . $this->writeUInt(0, 4, $littleEndian)
                . $this->writeUInt($noteAlignment, 8, $littleEndian)
                . $this->writeUInt(0, 8, $littleEndian);
        }
        return $this->writeUInt($nameOffset, 4, $littleEndian)
            . $this->writeUInt(self::SHT_NOTE, 4, $littleEndian)
            . $this->writeUInt(0, 4, $littleEndian)
            . $this->writeUInt(0, 4, $littleEndian)
            . $this->writeUInt($noteOffset, 4, $littleEndian)
            . $this->writeUInt($noteSize, 4, $littleEndian)
            . $this->writeUInt(0, 4, $littleEndian)
            . $this->writeUInt(0, 4, $littleEndian)
            . $this->writeUInt($noteAlignment, 4, $littleEndian)
            . $this->writeUInt(0, 4, $littleEndian);
    }

    private function updateSectionRange(
        string $header,
        int $class,
        bool $littleEndian,
        int $offset,
        int $size
    ): string {
        $offsetField = $class === self::ELFCLASS64 ? 0x18 : 0x10;
        $sizeField = $class === self::ELFCLASS64 ? 0x20 : 0x14;
        $width = $class === self::ELFCLASS64 ? 8 : 4;
        $header = substr_replace($header, $this->writeUInt($offset, $width, $littleEndian), $offsetField, $width);
        return substr_replace($header, $this->writeUInt($size, $width, $littleEndian), $sizeField, $width);
    }

    private function updateExtendedSectionNumbering(
        string $header,
        int $class,
        bool $littleEndian,
        int $sectionCount,
        int $stringIndex
    ): string {
        $sizeField = $class === self::ELFCLASS64 ? 0x20 : 0x14;
        $sizeWidth = $class === self::ELFCLASS64 ? 8 : 4;
        $extendedCount = $sectionCount >= self::SHN_LORESERVE ? $sectionCount : 0;
        $extendedStringIndex = $stringIndex >= self::SHN_LORESERVE ? $stringIndex : 0;
        $header = substr_replace(
            $header,
            $this->writeUInt($extendedCount, $sizeWidth, $littleEndian),
            $sizeField,
            $sizeWidth
        );
        return substr_replace(
            $header,
            $this->writeUInt($extendedStringIndex, 4, $littleEndian),
            $class === self::ELFCLASS64 ? 0x28 : 0x18,
            4
        );
    }

    private function parseSectionHeader(string $header, int $class, bool $littleEndian): array {
        if ($class === self::ELFCLASS64) {
            return [
                'name' => $this->readUInt($header, 0x00, 4, $littleEndian),
                'type' => $this->readUInt($header, 0x04, 4, $littleEndian),
                'flags' => $this->readUInt($header, 0x08, 8, $littleEndian),
                'offset' => $this->readUInt($header, 0x18, 8, $littleEndian),
                'size' => $this->readUInt($header, 0x20, 8, $littleEndian),
                'link' => $this->readUInt($header, 0x28, 4, $littleEndian),
                'info' => $this->readUInt($header, 0x2c, 4, $littleEndian),
                'alignment' => $this->readUInt($header, 0x30, 8, $littleEndian),
            ];
        }
        return [
            'name' => $this->readUInt($header, 0x00, 4, $littleEndian),
            'type' => $this->readUInt($header, 0x04, 4, $littleEndian),
            'flags' => $this->readUInt($header, 0x08, 4, $littleEndian),
            'offset' => $this->readUInt($header, 0x10, 4, $littleEndian),
            'size' => $this->readUInt($header, 0x14, 4, $littleEndian),
            'link' => $this->readUInt($header, 0x18, 4, $littleEndian),
            'info' => $this->readUInt($header, 0x1c, 4, $littleEndian),
            'alignment' => $this->readUInt($header, 0x20, 4, $littleEndian),
        ];
    }

    private function parseSectionZero(string $header, int $class, bool $littleEndian): array {
        if ($class === self::ELFCLASS64) {
            return [
                'size' => $this->readUInt($header, 0x20, 8, $littleEndian),
                'link' => $this->readUInt($header, 0x28, 4, $littleEndian),
                'info' => $this->readUInt($header, 0x2c, 4, $littleEndian),
            ];
        }
        return [
            'size' => $this->readUInt($header, 0x14, 4, $littleEndian),
            'link' => $this->readUInt($header, 0x18, 4, $littleEndian),
            'info' => $this->readUInt($header, 0x1c, 4, $littleEndian),
        ];
    }

    private function parseProgramHeader(string $header, int $class, bool $littleEndian): array {
        if ($class === self::ELFCLASS64) {
            return [
                'type' => $this->readUInt($header, 0x00, 4, $littleEndian),
                'offset' => $this->readUInt($header, 0x08, 8, $littleEndian),
                'fileSize' => $this->readUInt($header, 0x20, 8, $littleEndian),
                'memorySize' => $this->readUInt($header, 0x28, 8, $littleEndian),
            ];
        }
        return [
            'type' => $this->readUInt($header, 0x00, 4, $littleEndian),
            'offset' => $this->readUInt($header, 0x04, 4, $littleEndian),
            'fileSize' => $this->readUInt($header, 0x10, 4, $littleEndian),
            'memorySize' => $this->readUInt($header, 0x14, 4, $littleEndian),
        ];
    }

    private function noteAlignment(int $class, int $sectionAlignment): int {
        if (in_array($sectionAlignment, [4, 8], true)) {
            return $sectionAlignment;
        }
        return $class === self::ELFCLASS64 ? 8 : 4;
    }

    private function containsFoxyNote(string $notes, bool $littleEndian, int $alignment): bool {
        $position = 0;
        while ($position < strlen($notes)) {
            if (strlen($notes) - $position < 12) {
                throw new \RuntimeException('ELF note section is truncated');
            }
            $nameSize = $this->readUInt($notes, $position, 4, $littleEndian);
            $descriptionSize = $this->readUInt($notes, $position + 4, 4, $littleEndian);
            $type = $this->readUInt($notes, $position + 8, 4, $littleEndian);
            $nameOffset = $position + 12;
            $descriptionOffset = $this->align($nameOffset + $nameSize, $alignment);
            $end = $this->align($descriptionOffset + $descriptionSize, $alignment);
            if ($nameSize > strlen($notes) - $nameOffset || $end > strlen($notes)) {
                throw new \RuntimeException('ELF note record is truncated');
            }
            $owner = substr($notes, $nameOffset, $nameSize);
            if ($owner === self::NOTE_OWNER && $type === self::NOTE_TYPE) {
                return true;
            }
            $position = $end;
        }
        return false;
    }

    private function readUInt(string $data, int $offset, int $width, bool $littleEndian): int {
        if ($offset < 0 || $width < 1 || $offset > strlen($data) - $width) {
            throw new \RuntimeException('ELF integer field is outside its structure');
        }
        $bytes = substr($data, $offset, $width);
        $value = match ($width) {
            2 => unpack($littleEndian ? 'v' : 'n', $bytes)[1],
            4 => unpack($littleEndian ? 'V' : 'N', $bytes)[1],
            8 => unpack($littleEndian ? 'P' : 'J', $bytes)[1],
            default => throw new \RuntimeException("Unsupported ELF integer width: {$width}"),
        };
        if (!is_int($value) || $value < 0) {
            throw new \RuntimeException('ELF unsigned integer exceeds the supported range');
        }
        return $value;
    }

    private function writeUInt(int $value, int $width, bool $littleEndian): string {
        if ($value < 0) {
            throw new \RuntimeException('ELF integer values must be non-negative');
        }
        if ($width === 2 && $value > 0xffff) {
            throw new \RuntimeException('ELF value exceeds 16 bits');
        }
        if ($width === 4 && $value > 0xffffffff) {
            throw new \RuntimeException('ELF value exceeds 32 bits');
        }
        return match ($width) {
            2 => pack($littleEndian ? 'v' : 'n', $value),
            4 => pack($littleEndian ? 'V' : 'N', $value),
            8 => pack($littleEndian ? 'P' : 'J', $value),
            default => throw new \RuntimeException("Unsupported ELF integer width: {$width}"),
        };
    }

    private function sectionNameEquals(string $table, int $offset, string $expected): bool {
        $expected .= "\x00";
        return $offset <= strlen($table) - strlen($expected)
            && substr_compare($table, $expected, $offset, strlen($expected)) === 0;
    }

    private function assertFileRange(int $fileSize, int $offset, int $size, string $context): void {
        if ($offset < 0 || $size < 0 || $offset > $fileSize || $size > $fileSize - $offset) {
            throw new \RuntimeException("{$context} is outside the ELF file");
        }
    }

    private function align(int $value, int $alignment): int {
        $remainder = $value % $alignment;
        return $remainder === 0 ? $value : $value + ($alignment - $remainder);
    }

    private function writeFileSafely(string $path, string $contents, ?int $mode): void {
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
                throw new \RuntimeException("Unable to write the complete ELF output: {$path}");
            }
            if ($mode !== null && !@chmod($temporary, $mode)) {
                throw new \RuntimeException("Unable to preserve ELF file mode for: {$path}");
            }
            if (@rename($temporary, $path)) {
                $temporary = '';
                return;
            }

            $backup = tempnam($directory, '.foxy-backup-');
            if ($backup === false || !@unlink($backup) || !@rename($path, $backup)) {
                throw new \RuntimeException("Unable to replace ELF output: {$path}");
            }
            try {
                if (!@rename($temporary, $path)) {
                    @rename($backup, $path);
                    throw new \RuntimeException("Unable to replace ELF output: {$path}");
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
}
