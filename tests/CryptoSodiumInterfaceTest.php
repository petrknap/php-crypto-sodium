<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CryptoSodiumInterfaceTest extends TestCase
{
    #[DataProvider('dataIsImplementedByClass')]
    public function testIsImplementedByClass(string $className): void
    {
        exec(
            sprintf(
                'php -r "require_once \'%s\'; abstract class C extends %s implements %s {}"',
                __DIR__ . '/../vendor/autoload.php',
                $className,
                CryptoSodiumInterface::class,
            ),
            $output,
            $resultCode,
        );

        self::assertEquals(0, $resultCode, implode(PHP_EOL, $output));
    }

    public static function dataIsImplementedByClass(): array
    {
        return [
            Aead\Aegis128L::class => [Aead\Aegis128L::class],
            Aead\Aegis256::class => [Aead\Aegis256::class],
            Aead\Aes256Gcm::class => [Aead\Aes256Gcm::class],
            Aead\ChaCha20Poly1305::class => [Aead\ChaCha20Poly1305::class],
            Box::class => [Box::class],
            SecretBox::class => [SecretBox::class],
            SecretStream\XChaCha20Poly1305::class => [SecretStream\XChaCha20Poly1305::class],
        ];
    }
}
