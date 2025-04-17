<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Optional\OptionalString;
use PetrKnap\Shorts\HasRequirements;
use SensitiveParameter;
use Throwable;

/* final */class Box implements KeyPairGenerator, KeyPairExtractor, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    /**
     * @deprecated
     *
     * @todo remove it
     */
    public const HEADER_BYTES = SODIUM_CRYPTO_BOX_NONCEBYTES;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_box_keypair_from_secretkey_and_publickey',
                'sodium_crypto_box_seed_keypair',
                'sodium_crypto_box_keypair',
                'sodium_crypto_box_secretkey',
                'sodium_crypto_box_publickey',
                'sodium_crypto_box',
                'sodium_crypto_box_open',
            ],
            constants: [
                'SODIUM_CRYPTO_BOX_NONCEBYTES',
            ],
        );
    }

    public function generateKeyPair(
        #[SensitiveParameter]
        string|null $seedOrSecretKey = null,
        string|null $publicKey = null,
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
     * @param non-empty-string $encryptionKeyPair senders private key and recipients public key
     *
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$encryptionKeyPair,
        string|null $nonce = null,
    ): CiphertextWithNonce {
        return $this->wrapEncryption(static function (string $message, string $nonce) use (&$encryptionKeyPair): string {
            return sodium_crypto_box($message, $nonce, $encryptionKeyPair);
        }, $message, $nonce, SODIUM_CRYPTO_BOX_NONCEBYTES);
    }

    /**
     * @param non-empty-string $decryptionKeyPair recipients private key and senders public key
     *
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        CiphertextWithNonce|string $ciphertext,
        #[SensitiveParameter]
        string &$decryptionKeyPair,
        string|null $nonce = null,
    ): string {
        return $this->wrapDecryption(static function (string $ciphertext, string $nonce) use (&$decryptionKeyPair): string {
            return OptionalString::ofFalsable(sodium_crypto_box_open($ciphertext, $nonce, $decryptionKeyPair))->orElseThrow(
                static fn () => new Exception\CouldNotDecryptData('sodium_crypto_box_open', $ciphertext),
            );
        }, $ciphertext, $nonce, SODIUM_CRYPTO_BOX_NONCEBYTES);
    }
}
