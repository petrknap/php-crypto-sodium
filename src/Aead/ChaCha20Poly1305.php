<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Aead;

use PetrKnap\CryptoSodium\CiphertextWithNonce;
use PetrKnap\CryptoSodium\CryptoSodiumTrait;
use PetrKnap\CryptoSodium\DataEraser;
use PetrKnap\CryptoSodium\Exception;
use PetrKnap\CryptoSodium\KeyGenerator;
use SensitiveParameter;

/**
 * @see sodium_crypto_aead_chacha20poly1305_encrypt()
 */
class ChaCha20Poly1305 implements KeyGenerator, DataEraser
{
    use CryptoSodiumTrait;

    public const HEADER_BYTES = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES;

    public function generateKey(): string
    {
        return sodium_crypto_aead_chacha20poly1305_keygen();
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$key,
        ?string $nonce = null,
        ?string $additionalData = null,
    ): CiphertextWithNonce {
        return $this->wrapEncryption(static function (string $message, string $nonce) use (&$key, $additionalData): string {
            $additionalData ??= '';
            return sodium_crypto_aead_chacha20poly1305_encrypt($message, $additionalData, $nonce, $key);
        }, $message, $nonce, self::HEADER_BYTES);
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        CiphertextWithNonce|string $ciphertext,
        #[SensitiveParameter]
        string &$key,
        ?string $nonce = null,
        ?string $additionalData = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$key, $additionalData): string {
            $additionalData ??= '';
            $message = sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $additionalData, $nonce, $key);
            if ($message === false) {
                throw new Exception\CouldNotDecryptData('sodium_crypto_aead_chacha20poly1305_decrypt', $ciphertext);
            }
            return $message;
        }, $ciphertext, $nonce, self::HEADER_BYTES);
    }
}
