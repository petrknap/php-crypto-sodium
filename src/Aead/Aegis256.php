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

/* final */class Aegis256 implements KeyGenerator, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_aead_aegis256_keygen',
                'sodium_crypto_aead_aegis256_encrypt',
                'sodium_crypto_aead_aegis256_decrypt',
            ],
            constants: [
                'SODIUM_CRYPTO_AEAD_AEGIS256_NPUBBYTES',
            ],
        );
    }

    public function generateKey(): string
    {
        return sodium_crypto_aead_aegis256_keygen();
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
            return sodium_crypto_aead_aegis256_encrypt($message, $additionalData ?? '', $nonce, $key);
        }, $message, $nonce, constant('SODIUM_CRYPTO_AEAD_AEGIS256_NPUBBYTES'));
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
            return OptionalString::ofFalsable(sodium_crypto_aead_aegis256_decrypt($ciphertext, $additionalData ?? '', $nonce, $key))->orElseThrow(
                static fn () => new Exception\CouldNotDecryptData('sodium_crypto_aead_aegis256_decrypt', $ciphertext),
            );
        }, $ciphertext, $nonce, constant('SODIUM_CRYPTO_AEAD_AEGIS256_NPUBBYTES'));
    }
}
