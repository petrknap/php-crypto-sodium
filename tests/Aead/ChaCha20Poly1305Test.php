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
        $this->ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('ptjBjxRJYS0N7V71OotUjNIdyNCVmv4lW4wQ6CA='),
            nonce: base64_decode('X7EcnUfvhWg='),
        );
        $this->encryptArgsSet = [
            [self::MESSAGE, $key, $this->ciphertextWithNonce->nonce, $additionalData],
        ];
        $this->decryptArgsSet = [
            [$this->ciphertextWithNonce, $key, null, $additionalData],
            [$this->ciphertextWithNonce->toString(), $key, null, $additionalData],
            [$this->ciphertextWithNonce->ciphertext, $key, $this->ciphertextWithNonce->nonce, $additionalData],
        ];
    }
}
