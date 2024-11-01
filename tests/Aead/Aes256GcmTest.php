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
        $this->ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('sycH81OWv2uCxygkUDpBq+Jy7SBl6zSuWjh4zTQ='),
            nonce: base64_decode('FJbSk+jybJUfvxrn'),
        );
        $this->encryptArgsSet = [
            [self::MESSAGE, $key, $this->ciphertextWithNonce->nonce, $additionalData],
        ];
        $this->decryptArgsSet = [
            [$this->ciphertextWithNonce, $key, null, $additionalData],
            [$this->ciphertextWithNonce->toBinary(), $key, null, $additionalData],
            [$this->ciphertextWithNonce->ciphertext, $key, $this->ciphertextWithNonce->nonce, $additionalData],
        ];
    }
}
