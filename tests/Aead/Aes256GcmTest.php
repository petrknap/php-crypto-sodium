<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Aead;

use PetrKnap\CryptoSodium\CiphertextWithNonce;
use PetrKnap\CryptoSodium\CryptoSodiumTestCase;

final class Aes256GcmTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new Aes256Gcm();
        $key = base64_decode('9+PiVpFGyLSks1UJlpgGL6VuxJ86zzaizKB5e0C3IE8=');
        $additionalData = 'AD';
        $ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('sycH81OWv2uCxygkUDpBq+Jy7SBl6zSuWjh4zTQ='),
            nonce: base64_decode('FJbSk+jybJUfvxrn'),
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
