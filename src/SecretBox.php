<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

/**
 * @see sodium_crypto_secretbox()
 */
class SecretBox implements KeyGenerator, DataEraser
{
    use CryptoSodiumTrait;

    /**
     * @deprecated
     *
     * @todo remove it
     */
    public const HEADER_BYTES = self::NONCE_BYTES;

    private const NONCE_BYTES = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

    public function generateKey(): string
    {
        return sodium_crypto_secretbox_keygen();
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$key,
        ?string $nonce = null,
    ): CiphertextWithNonce {
        return $this->wrapEncryption(static function (string $message, string $nonce) use (&$key): string {
            return sodium_crypto_secretbox($message, $nonce, $key);
        }, $message, $nonce, self::NONCE_BYTES);
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        CiphertextWithNonce|string $ciphertext,
        #[SensitiveParameter]
        string &$key,
        ?string $nonce = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$key): string {
            $message = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
            if ($message === false) {
                throw new Exception\CouldNotDecryptData('sodium_crypto_secretbox_open', $ciphertext);
            }
            return $message;
        }, $ciphertext, $nonce, self::NONCE_BYTES);
    }
}
