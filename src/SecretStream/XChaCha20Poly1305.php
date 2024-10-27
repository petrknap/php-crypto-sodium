<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\SecretStream;

use PetrKnap\Binary\Binary;
use PetrKnap\CryptoSodium\CryptoSodiumInterface;
use PetrKnap\CryptoSodium\CryptoSodiumTrait;
use PetrKnap\CryptoSodium\DataEraser;
use PetrKnap\CryptoSodium\Exception;
use PetrKnap\CryptoSodium\HeadedCipher;
use PetrKnap\CryptoSodium\KeyGenerator;
use PetrKnap\CryptoSodium\MessageWithTag;
use PetrKnap\CryptoSodium\PullStream;
use PetrKnap\CryptoSodium\PushStream;
use PetrKnap\CryptoSodium\Stream;
use PetrKnap\Optional\OptionalArray;
use PetrKnap\Shorts\HasRequirements;
use SensitiveParameter;
use Throwable;

/* final */class XChaCha20Poly1305 implements HeadedCipher, KeyGenerator, DataEraser
{
    use HasRequirements;
    use CryptoSodiumTrait;

    /**
     * @deprecated use {@see self::getHeaderSize()}
     *
     * @todo remove it
     */
    public const HEADER_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
    public const TAG_MESSAGE = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
    /** @link https://doc.libsodium.org/secret-key_cryptography/secretstream#rekeying */
    public const TAG_REKEY = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY;
    public const TAG_PUSH = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH;
    public const TAG_FINAL = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    /** @internal there is no reason to use it from the outside */
    public const DEFAULT_TAG = self::TAG_MESSAGE;

    public function __construct()
    {
        self::checkRequirements(
            functions: [
                'sodium_crypto_secretstream_xchacha20poly1305_keygen',
                'sodium_crypto_secretstream_xchacha20poly1305_init_push',
                'sodium_crypto_secretstream_xchacha20poly1305_push',
                'sodium_crypto_secretstream_xchacha20poly1305_init_pull',
                'sodium_crypto_secretstream_xchacha20poly1305_pull',
            ],
            constants: [
                'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES',
                'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE',
                'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY',
                'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH',
                'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL',
            ],
        );
    }

    public function getHeaderSize(): int
    {
        return self::HEADER_BYTES;
    }

    public function generateKey(): string
    {
        return sodium_crypto_secretstream_xchacha20poly1305_keygen();
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function initPush(
        #[SensitiveParameter]
        string &$key,
    ): PushStream {
        return $this->wrapPush(function () use (&$key): PushStream {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            /** @var CryptoSodiumInterface $instance */
            $instance = $this;
            return new PushStream(
                instance: $instance,
                state: $state,
                header: $header,
            );
        }, '', null);
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function push(
        PushStream &$stream,
        MessageWithTag|string $message,
        int|null $tag = null,
        string|null $additionalData = null,
    ): string {
        return $this->wrapPush(function (string $message, int|null $tag) use (&$stream, $additionalData): string {
            $tag ??= self::DEFAULT_TAG;
            $additionalData ??= '';
            $ciphertext = sodium_crypto_secretstream_xchacha20poly1305_push($stream->state, $message, $additionalData, $tag);
            $this->updateStream($stream, $tag);
            return $ciphertext;
        }, $message, $tag);
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function initPull(
        PushStream|string $header,
        #[SensitiveParameter]
        string &$key,
    ): PullStream {
        return $this->wrapPull(function (string $header) use (&$key): PullStream {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
            /** @var CryptoSodiumInterface $instance */
            $instance = $this;
            return new PullStream(
                instance: $instance,
                state: $state,
                aBytes: SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
            );
        }, Binary::asBinary($header));
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function pull(
        PullStream &$stream,
        string $ciphertext,
        string|null $additionalData = null,
    ): MessageWithTag {
        return $this->wrapPull(function (string $ciphertext) use (&$stream, $additionalData): MessageWithTag {
            /**
             * @var string $message
             * @var int $tag
             */
            [$message, $tag] = OptionalArray::ofFalsable(sodium_crypto_secretstream_xchacha20poly1305_pull($stream->state, $ciphertext, $additionalData ?? ''))->orElseThrow(
                static fn () => new Exception\CouldNotDecryptData('sodium_crypto_secretstream_xchacha20poly1305_pull', $ciphertext),
            );
            $this->updateStream($stream, $tag);
            return new MessageWithTag(
                message: $message,
                tag: $tag,
            );
        }, $ciphertext);
    }

    /**
     * @throws Exception\CouldNotRekey
     */
    public function rekey(
        Stream &$stream,
    ): void {
        try {
            sodium_crypto_secretstream_xchacha20poly1305_rekey($stream->state);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotRekey($reason);
        }
    }

    private function updateStream(
        Stream &$stream,
        int $tag,
    ): void {
        if ($tag == self::TAG_FINAL) {
            $this->eraseData($stream->state);
        }
    }
}
