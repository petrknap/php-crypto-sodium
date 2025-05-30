<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

/**
 * @internal template
 */
interface CryptoSodiumInterface
{
    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$_,
    ): CiphertextWithNonce;

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        CiphertextWithNonce|string $ciphertext,
        #[SensitiveParameter]
        string &$_,
        string|null $nonce = null,
    ): string;

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function initPush(
        #[SensitiveParameter]
        string &$_,
    ): PushStream;

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function push(
        PushStream &$stream,
        MessageWithTag|string $message,
        int|null $tag = null,
    ): string; // @todo return Ciphertext

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function initPull(
        PushStream|string $header,
        #[SensitiveParameter]
        string &$_,
    ): PullStream;

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function pull(
        PullStream &$stream,
        string $ciphertext,
    ): MessageWithTag;

    /**
     * @throws Exception\CouldNotRekey
     */
    public function rekey(
        Stream &$stream,
    ): void;

    /**
     * @throws Exception\CouldNotSignData
     */
    public function sign(
        string $message,
        #[SensitiveParameter]
        string &$_,
    ): string; // @todo return SignedMessage

    /**
     * @throws Exception\CouldNotSignData
     */
    public function signDetached(
        string $message,
        #[SensitiveParameter]
        string &$_,
    ): string; // @todo return Signature

    /**
     * @throws Exception\CouldNotVerifyData
     */
    public function verified(
        string $signedMessage,
        #[SensitiveParameter]
        string &$_,
    ): string;

    public function verifyDetached(
        string $signature,
        string $message,
        #[SensitiveParameter]
        string &$_,
    ): bool;
}
