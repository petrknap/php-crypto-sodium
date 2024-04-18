<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\TestCase;

abstract class CryptoSodiumTestCase extends TestCase
{
    protected const MESSAGE = 'Hello, World!';
    protected object $instance;
    protected CiphertextWithNonce $ciphertextWithNonce;
    protected array $encryptArgsSet = [];
    protected array $decryptArgsSet = [];

    public function testEncrypts(): void
    {
        if (empty($this->encryptArgsSet)) {
            self::markTestSkipped();
        }

        foreach ($this->encryptArgsSet as $name => $encryptArgs) {
            self::assertSame(
                bin2hex((string)$this->ciphertextWithNonce),
                bin2hex((string)call_user_func_array([$this->instance, 'encrypt'], $encryptArgs)),
                "{$name} failed",
            );
        }
    }

    public function testDecrypts(): void
    {
        if (empty($this->decryptArgsSet)) {
            self::markTestSkipped();
        }

        foreach ($this->decryptArgsSet as $name => $decryptArgs) {
            self::assertSame(
                static::MESSAGE,
                call_user_func_array([$this->instance, 'decrypt'], $decryptArgs),
                "{$name} failed",
            );
        }
    }

    public function testWorksWithOwnKeyPair(): void
    {
        if (!($this->instance instanceof KeyPairGenerator && $this->instance instanceof KeyPairExtractor)) {
            self::markTestSkipped();
        }

        $keyPair = $this->instance->generateKeyPair();

        self::assertSame(
            $keyPair,
            $this->instance->generateKeyPair(
                $this->instance->extractSecretKey($keyPair),
                $this->instance->extractPublicKey($keyPair),
            ),
        );
    }
}
