<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use InvalidArgumentException;
use PetrKnap\Binary\Binary;
use SensitiveParameter;
use Throwable;

/**
 * @internal helper
 */
trait CryptoSodiumTrait
{
    /**
     * @param callable(string, string): string $encrypt message with nonce
     * @param int<1, max> $nonceBytes
     *
     * @throws Exception\CouldNotEncryptData
     */
    private function wrapEncryption(
        callable $encrypt,
        string $message,
        ?string $nonce,
        int $nonceBytes,
    ): CiphertextWithNonce {
        try {
            $nonce ??= random_bytes($nonceBytes);
            $ciphertext = $encrypt($message, $nonce);
            return new CiphertextWithNonce(
                ciphertext: $ciphertext,
                nonce: $nonce,
            );
        } catch (Exception\CouldNotEncryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotEncryptData(__METHOD__, $message, $reason);
        }
    }

    /**
     * @param callable(string, string): string $decrypt ciphertext with nonce
     * @param int<1, max> $nonceBytes
     *
     * @throws Exception\CouldNotDecryptData
     */
    private function wrapDecryption(
        callable $decrypt,
        CiphertextWithNonce|string $ciphertext,
        ?string $nonce,
        int $nonceBytes,
    ): string {
        try {
            if ($nonce !== null) {
                if ($ciphertext instanceof CiphertextWithNonce) {
                    throw new InvalidArgumentException('$ciphertext must be string, or $nonce must be null');
                }
                $ciphertextWithNonce = new CiphertextWithNonce(
                    ciphertext: $ciphertext,
                    nonce: $nonce,
                );
            } else {
                if (is_string($ciphertext)) {
                    $ciphertextWithNonce = CiphertextWithNonce::fromBinary(
                        ciphertextWithNonce: $ciphertext,
                        nonceBytes: $nonceBytes,
                    );
                } else {
                    $ciphertextWithNonce = $ciphertext;
                }
            }
            return $decrypt($ciphertextWithNonce->ciphertext, $ciphertextWithNonce->nonce);
        } catch (Exception\CouldNotDecryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotDecryptData(__METHOD__, Binary::asBinary($ciphertext), $reason);
        }
    }

    /**
     * @template TOutput of PushStream|string
     *
     * @param callable(string, ?int): TOutput $push message with tag
     *
     * @return TOutput
     *
     * @throws Exception\CouldNotEncryptData
     */
    private function wrapPush(callable $push, MessageWithTag|string $message, ?int $tag): PushStream|string
    {
        try {
            if ($message instanceof MessageWithTag) {
                if ($tag !== null) {
                    throw new InvalidArgumentException('$message must be string, or $tag must be null');
                }
                $tag = $message->tag;
                $message = $message->message;
            }
            return $push($message, $tag);
        } catch (Exception\CouldNotEncryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotEncryptData(__METHOD__, Binary::asBinary($message), $reason);
        }
    }

    /**
     * @template TOutput of PullStream|MessageWithTag
     *
     * @param callable(string): TOutput $pull ciphertext
     *
     * @return TOutput
     *
     * @throws Exception\CouldNotDecryptData
     */
    private function wrapPull(callable $pull, string $ciphertext): PullStream|MessageWithTag
    {
        try {
            return $pull($ciphertext);
        } catch (Exception\CouldNotDecryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotDecryptData(__METHOD__, $ciphertext, $reason);
        }
    }

    public function eraseData(
        #[SensitiveParameter]
        string &$data,
    ): void {
        try {
            sodium_memzero($data);
        } catch (Throwable $reason) {
            throw new Exception\CouldNotEraseData($reason);
        }
    }
}
