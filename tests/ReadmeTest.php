<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Shorts\PhpUnit\MarkdownFileTestInterface;
use PetrKnap\Shorts\PhpUnit\MarkdownFileTestTrait;
use PHPUnit\Framework\TestCase;

class ReadmeTest extends TestCase implements MarkdownFileTestInterface
{
    use MarkdownFileTestTrait;

    public static function getPathToMarkdownFile(): string
    {
        return __DIR__ . '/../README.md';
    }

    public static function getExpectedOutputsOfPhpExamples(): iterable
    {
        return [
            SecretBox::class => 'bool(true)' . PHP_EOL,
            Box::class => 'bool(true)' . PHP_EOL,
        ];
    }
}
