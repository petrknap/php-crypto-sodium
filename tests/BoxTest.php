<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

final class BoxTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->instance = new Box();
        $keyPair = $this->instance->generateKeyPair(base64_decode('o8DJ9Tp7MT0nOjzzpnrjNQswHHJgwVKrtGgzwWlflaM='));
        $this->ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('B9845kOUP8d1kk9bQBWrvB7umkrgX7pgjIsXNb0='),
            nonce: base64_decode('mXVQMM6ud/69jDTsIGHTuNrktqcCebQR'),
        );
        $this->encryptArgsSet = [
            [self::MESSAGE, $keyPair, $this->ciphertextWithNonce->nonce],
        ];
        $this->decryptArgsSet = [
            [$this->ciphertextWithNonce, $keyPair],
            [$this->ciphertextWithNonce->toBinary(), $keyPair],
            [$this->ciphertextWithNonce->ciphertext, $keyPair, $this->ciphertextWithNonce->nonce],
        ];
    }

    public function testKeyPairGeneratorThrowsOnWrongSeed(): void
    {
        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong seed');
    }

    public function testKeyPairGeneratorThrowsOnWrongKeys(): void
    {
        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong secret key', 'wrong public key');
    }
}
