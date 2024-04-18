<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\TestCase;

abstract class CryptoSodiumTestCase extends TestCase
{
    protected const MESSAGE = 'Hello, World!';
    protected object $instance;
    protected array $encryptArgs;
    protected string $ciphertextWithNonce;
    protected array $decryptArgs;

    public function testEncrypts(): void
    {
        self::assertSame(
            bin2hex($this->ciphertextWithNonce),
            bin2hex(call_user_func_array([$this->instance, 'encrypt'], $this->encryptArgs)),
        );
    }

    public function testDecrypts(): void
    {
        self::assertSame(
            static::MESSAGE,
            call_user_func_array([$this->instance, 'decrypt'], $this->decryptArgs),
        );
    }
}
