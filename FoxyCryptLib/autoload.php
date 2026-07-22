<?php
declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $prefix = 'FoxyCryptLib\\';
    $baseDir = __DIR__ . '/src/';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) return;

    $relativeClass = substr($class, strlen($prefix));
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});
