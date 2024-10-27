<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Optional\OptionalString;
use PetrKnap\Shorts\HasRequirements;
use SensitiveParameter;

/* final */class SecretBox implements KeyGenerator, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    /**
     * @deprecated
     *
     * @todo remove it
     */
    public const HEADER_BYTES = self::NONCE_BYTES;

    private const NONCE_BYTES = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_secretbox_keygen',
                'sodium_crypto_secretbox',
                'sodium_crypto_secretbox_open',
            ],
            constants: [
                'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES',
            ],
        );
    }

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
        string|null $nonce = null,
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
        string|null $nonce = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$key): string {
            return OptionalString::ofFalsable(sodium_crypto_secretbox_open($ciphertext, $nonce, $key))->orElseThrow(
                static fn () => new Exception\CouldNotDecryptData('sodium_crypto_secretbox_open', $ciphertext),
            );
        }, $ciphertext, $nonce, self::NONCE_BYTES);
    }
}
