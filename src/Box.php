<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;
use Throwable;

/**
 * @see sodium_crypto_box()
 */
class Box implements KeyPairGenerator, KeyPairExtractor, DataEraser
{
    use CryptoSodiumTrait;

    public const HEADER_BYTES = SODIUM_CRYPTO_BOX_NONCEBYTES;

    public function generateKeyPair(
        #[SensitiveParameter]
        ?string $seedOrSecretKey = null,
        ?string $publicKey = null,
    ): string {
        try {
            if ($seedOrSecretKey !== null && $publicKey !== null) {
                return sodium_crypto_box_keypair_from_secretkey_and_publickey($seedOrSecretKey, $publicKey);
            }
            if ($seedOrSecretKey !== null) {
                return sodium_crypto_box_seed_keypair($seedOrSecretKey);
            }
            return sodium_crypto_box_keypair();
        } catch (Throwable $reason) {
            throw new Exception\CouldNotGenerateKeyPair($reason);
        }
    }

    public function extractSecretKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string {
        try {
            return sodium_crypto_box_secretkey($keyPair);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotExtractSecretKey($reason);
        }
    }

    public function extractPublicKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string {
        try {
            return sodium_crypto_box_publickey($keyPair);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotExtractPublicKey($reason);
        }
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$keyPair,
        ?string $nonce = null,
    ): CiphertextWithNonce {
        return $this->wrapEncryption(static function (string $message, string $nonce) use (&$keyPair): string {
            return sodium_crypto_box($message, $nonce, $keyPair);
        }, $message, $nonce, self::HEADER_BYTES);
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        CiphertextWithNonce|string $ciphertext,
        #[SensitiveParameter]
        string &$keyPair,
        ?string $nonce = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$keyPair): string {
            $message = sodium_crypto_box_open($ciphertext, $nonce, $keyPair);
            if ($message === false) {
                throw new Exception\CouldNotDecryptData('sodium_crypto_box_open', $ciphertext);
            }
            return $message;
        }, $ciphertext, $nonce, self::HEADER_BYTES);
    }
}
