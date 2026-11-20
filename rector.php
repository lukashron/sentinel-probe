<?php declare(strict_types=1);

use Rector\CodingStyle\Rector\Catch_\CatchExceptionNameMatchingTypeRector;
use Rector\CodingStyle\Rector\Encapsed\EncapsedStringsToSprintfRector;
use Rector\CodingStyle\Rector\Stmt\NewlineAfterStatementRector;
use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/src',
    ])
    // PHP version is taken from composer.json (>=8.3)
    ->withPhpSets()
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        codingStyle: true,
        typeDeclarations: true,
        privatization: true,
        instanceOf: true,
        earlyReturn: true,
    )
    ->withComposerBased(symfony: true)
    ->withImportNames(importShortClasses: false, removeUnusedImports: true)
    ->withSkip([
        // keeps short names like $e instead of $transportException
        CatchExceptionNameMatchingTypeRector::class,
        // "...{$var}..." strings are fine, no forced sprintf()
        EncapsedStringsToSprintfRector::class,
        // leaves blank lines between statements up to the author
        NewlineAfterStatementRector::class,
    ]);
