<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Aead;

use PetrKnap\CryptoSodium\CiphertextWithNonce;
use PetrKnap\CryptoSodium\CryptoSodiumTestCase;

final class ChaCha20Poly1305Test extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new ChaCha20Poly1305();
        $key = base64_decode('FVGZ9cOoCVzHJSMPxEHdKauic4YAf9aD2qc1+cB6oxU=');
        $additionalData = 'AD';
        $ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('ptjBjxRJYS0N7V71OotUjNIdyNCVmv4lW4wQ6CA='),
            nonce: base64_decode('X7EcnUfvhWg='),
        );

        $this->encryptArgsSet = [
            [self::MESSAGE, $key, $ciphertextWithNonce->nonce, $additionalData],
        ];
        $this->encrypted = $ciphertextWithNonce->toBinary();

        $this->decryptArgsSet = [
            [$this->encrypted, $key, null, $additionalData],
            [$ciphertextWithNonce, $key, null, $additionalData],
            [$ciphertextWithNonce->ciphertext, $key, $ciphertextWithNonce->nonce, $additionalData],
        ];
    }
}
