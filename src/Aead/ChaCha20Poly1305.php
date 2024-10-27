<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Aead;

use PetrKnap\CryptoSodium\CiphertextWithNonce;
use PetrKnap\CryptoSodium\CryptoSodiumTrait;
use PetrKnap\CryptoSodium\DataEraser;
use PetrKnap\CryptoSodium\Exception;
use PetrKnap\CryptoSodium\KeyGenerator;
use PetrKnap\Optional\OptionalString;
use PetrKnap\Shorts\HasRequirements;
use SensitiveParameter;

/* final */class ChaCha20Poly1305 implements KeyGenerator, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    /**
     * @deprecated
     *
     * @todo remove it
     */
    public const HEADER_BYTES = self::NONCE_BYTES;

    private const NONCE_BYTES = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_aead_chacha20poly1305_keygen',
                'sodium_crypto_aead_chacha20poly1305_encrypt',
                'sodium_crypto_aead_chacha20poly1305_decrypt',
            ],
            constants: [
                'SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES',
            ],
        );
    }

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
        string|null $nonce = null,
        string|null $additionalData = null,
    ): CiphertextWithNonce {
        return $this->wrapEncryption(static function (string $message, string $nonce) use (&$key, $additionalData): string {
            return sodium_crypto_aead_chacha20poly1305_encrypt($message, $additionalData ?? '', $nonce, $key);
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
        string|null $additionalData = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$key, $additionalData): string {
            return OptionalString::ofFalsable(sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $additionalData ?? '', $nonce, $key))->orElseThrow(
                static fn () => new Exception\CouldNotDecryptData('sodium_crypto_aead_chacha20poly1305_decrypt', $ciphertext),
            );
        }, $ciphertext, $nonce, self::NONCE_BYTES);
    }
}
