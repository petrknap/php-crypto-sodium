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
        $ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('B9845kOUP8d1kk9bQBWrvB7umkrgX7pgjIsXNb0='),
            nonce: base64_decode('mXVQMM6ud/69jDTsIGHTuNrktqcCebQR'),
        );

        $this->encryptArgsSet = [
            [self::MESSAGE, $keyPair, $ciphertextWithNonce->nonce],
        ];
        $this->encrypted = $ciphertextWithNonce->toBinary();

        $this->decryptArgsSet = [
            [$this->encrypted, $keyPair],
            [$ciphertextWithNonce, $keyPair],
            [$ciphertextWithNonce->ciphertext, $keyPair, $ciphertextWithNonce->nonce],
        ];
    }
}
