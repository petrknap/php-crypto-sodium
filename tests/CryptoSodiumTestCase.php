<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\TestCase;

abstract class CryptoSodiumTestCase extends TestCase
{
    protected const MESSAGE = 'Hello, World!';

    /** @var CryptoSodiumInterface|object */
    protected object $instance;
    protected CiphertextWithNonce $ciphertextWithNonce;
    protected array $encryptArgsSet = [];
    protected array $decryptArgsSet = [];
    protected array $pushArgsSet = [];

    public function testEncrypts(): void
    {
        if (empty($this->encryptArgsSet)) {
            self::markTestSkipped();
        }

        foreach ($this->encryptArgsSet as $name => $encryptArgs) {
            self::assertSame(
                bin2hex((string) $this->ciphertextWithNonce),
                bin2hex((string) $this->instance->encrypt(...$encryptArgs)),
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
                $this->instance->decrypt(...$decryptArgs),
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
}
