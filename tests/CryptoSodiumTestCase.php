<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\TestCase;

abstract class CryptoSodiumTestCase extends TestCase
{
    protected const MESSAGE = 'Hello, World!';

    /** @var CryptoSodiumInterface|object */
    protected object $instance;
    /** @todo replace it by string $encryptedMessage */
    protected CiphertextWithNonce $ciphertextWithNonce;
    protected string $encryptMethodName = 'encrypt';
    protected array $encryptArgsSet = [];
    protected string $decryptMethodName = 'decrypt';
    protected array $decryptArgsSet = [];
    protected array $pushArgsSet = [];

    public function testEncrypts(): void
    {
        if (!method_exists($this->instance, $this->encryptMethodName)) {
            self::markTestSkipped();
        }

        foreach ($this->encryptArgsSet as $name => $encryptArgs) {
            self::assertSame(
                bin2hex((string) $this->ciphertextWithNonce),
                bin2hex((string) $this->instance->{$this->encryptMethodName}(...$encryptArgs)),
                "{$name} failed",
            );
        }
    }

    public function testDecrypts(): void
    {
        if (!method_exists($this->instance, $this->decryptMethodName)) {
            self::markTestSkipped();
        }

        foreach ($this->decryptArgsSet as $name => $decryptArgs) {
            self::assertSame(
                static::MESSAGE,
                $this->instance->{$this->decryptMethodName}(...$decryptArgs),
                "{$name} failed",
            );
        }
    }

    public function testPushesAndPulls(): void
    {
        if (empty($this->pushArgsSet)) {
            self::markTestSkipped();
        }

        $key = $this->instance->generateKey();
        $pushStream = $this->instance->initPush($key);
        $messages = [];
        $additionalData = [];
        $ciphertexts = [];
        foreach ($this->pushArgsSet as $pushArgs) {
            $message = $pushArgs[0];
            if (is_string($message)) {
                $tag = $pushArgs[1] ?? constant($this->instance::class . '::DEFAULT_TAG');
                $message = new MessageWithTag($message, $tag);
            }
            $messages[] = $message;
            $additionalData[] = $pushArgs[2] ?? null;
            $ciphertexts[] = $pushStream->push(...$pushArgs);
        }
        $pullStream = $this->instance->initPull($pushStream, $key);
        foreach ($ciphertexts as $i => $ciphertext) {
            self::assertEquals(
                $messages[$i],
                $pullStream->pull($ciphertext, $additionalData[$i]),
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

    public function testKeyPairGeneratorThrowsOnWrongSeed(): void
    {
        if (!($this->instance instanceof KeyPairGenerator)) {
            self::markTestSkipped();
        }

        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong seed');
    }

    public function testKeyPairGeneratorThrowsOnWrongKeys(): void
    {
        if (!($this->instance instanceof KeyPairGenerator)) {
            self::markTestSkipped();
        }

        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong secret key', 'wrong public key');
    }
}
