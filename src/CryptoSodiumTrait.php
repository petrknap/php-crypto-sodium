<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use InvalidArgumentException;
use SensitiveParameter;
use Throwable;

/**
 * @internal helper
 */
trait CryptoSodiumTrait
{
    /**
     * @param callable(string, string): string $encrypt message with nonce
     *
     * @throws Exception\CouldNotEncryptData
     */
    private function wrapEncryption(callable $encrypt, string $message, ?string $nonce): CiphertextWithNonce
    {
        try {
            $nonce ??= random_bytes(self::NONCE_BYTES);
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
     *
     * @throws Exception\CouldNotDecryptData
     */
    private function wrapDecryption(callable $decrypt, CiphertextWithNonce|string $ciphertext, ?string $nonce): string
    {
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
                    $ciphertextWithNonce = CiphertextWithNonce::fromString(
                        ciphertext: $ciphertext,
                        nonceBytes: self::NONCE_BYTES,
                    );
                } else {
                    $ciphertextWithNonce = $ciphertext;
                }
            }
            return $decrypt($ciphertextWithNonce->ciphertext, $ciphertextWithNonce->nonce);
        } catch (Exception\CouldNotDecryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotDecryptData(__METHOD__, (string) $ciphertext, $reason);
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
