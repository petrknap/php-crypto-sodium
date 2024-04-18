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
                'php -r "require_once \'%s\'; final class C extends %s implements %s {}"',
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
            SecretBox::class => [SecretBox::class],
        ];
    }
}
