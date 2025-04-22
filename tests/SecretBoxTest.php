<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

final class SecretBoxTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new SecretBox();
        $key = base64_decode('4ayqwrn6R6uy4oyQyoOnowdosil5ZPPqKtFtCj5WkjQ=');
        $ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('reUOODrutLarlV3PBYoLmRShxivRqzIJqDJto74='),
            nonce: base64_decode('mXVQMM6ud/69jDTsIGHTuNrktqcCebQR'),
        );

        $this->encryptArgsSet = [
            [self::MESSAGE, $key, $ciphertextWithNonce->nonce],
        ];
        $this->encrypted = $ciphertextWithNonce->toBinary();

        $this->decryptArgsSet = [
            [$this->encrypted, $key],
            [$ciphertextWithNonce, $key],
            [$ciphertextWithNonce->ciphertext, $key, $ciphertextWithNonce->nonce],
        ];
    }
}
