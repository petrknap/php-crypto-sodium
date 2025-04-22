<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\Binary;
use PetrKnap\Optional\OptionalString;
use PetrKnap\Shorts\HasRequirements;
use SensitiveParameter;
use Throwable;

/* final */class Sign implements KeyPairGenerator, KeyPairExtractor, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_sign_keypair_from_secretkey_and_publickey',
                'sodium_crypto_sign_seed_keypair',
                'sodium_crypto_sign_keypair',
                'sodium_crypto_sign_secretkey',
                'sodium_crypto_sign_publickey',
                'sodium_crypto_sign',
                'sodium_crypto_sign_open',
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
                return sodium_crypto_sign_keypair_from_secretkey_and_publickey($seedOrSecretKey, $publicKey);
            }
            if ($seedOrSecretKey !== null) {
                return sodium_crypto_sign_seed_keypair($seedOrSecretKey);
            }
            return sodium_crypto_sign_keypair();
        } catch (Throwable $reason) {
            throw new Exception\CouldNotGenerateKeyPair($reason);
        }
    }

    public function extractSecretKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string {
        try {
            return sodium_crypto_sign_secretkey($keyPair);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotExtractSecretKey($reason);
        }
    }

    public function extractPublicKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string {
        try {
            return sodium_crypto_sign_publickey($keyPair);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotExtractPublicKey($reason);
        }
    }

    /**
     * @param non-empty-string $secretKey
     *
     * @return non-empty-string signed message
     *
     * @throws Exception\CouldNotSignData
     */
    public function sign(
        string $message,
        #[SensitiveParameter]
        string &$secretKey,
    ): string {
        try {
            return sodium_crypto_sign($message, $secretKey);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotSignData(__METHOD__, $message, $reason);
        }
    }

    /**
     * @param non-empty-string $signedMessage
     * @param non-empty-string $publicKey
     *
     * @return string message
     *
     * @throws Exception\CouldNotVerifyData
     */
    public function verified(
        string $signedMessage,
        #[SensitiveParameter]
        string &$publicKey,
    ): string {
        try {
            return OptionalString::ofFalsable(
                sodium_crypto_sign_open($signedMessage, $publicKey),
            )->orElseThrow(
                static fn() => new Exception\CouldNotVerifyData('sodium_crypto_sign_open', $signedMessage),
            );
        } catch (Exception\CouldNotVerifyData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotVerifyData(__METHOD__, $signedMessage, $reason);
        }
    }
}
