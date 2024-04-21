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
            SecretBox::class => 'Hello World!',
            Box::class => 'Hello World!',
            SecretStream\XChaCha20Poly1305::class => 'Hello World!',
            Aead\Aes256Gcm::class => 'Hello World!',
        ];
    }
}
