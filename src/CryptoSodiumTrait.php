<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\Byter;
use RuntimeException;
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
    private function wrapEncryption(callable $encrypt, string $message, ?string $nonce = null): string
    {
        try {
            $nonce ??= random_bytes(self::NONCE_BYTES);
            $ciphertext = $encrypt($message, $nonce);
            return (new Byter())->unbite(self::IDENTIFIER->toBinary(), $nonce, $ciphertext);
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
    private function wrapDecryption(callable $decrypt, string $ciphertextWithHeader): string
    {
        try {
            [$identifier, $nonce, $ciphertext] = (new Byter())->bite($ciphertextWithHeader, Identifier::BYTES, self::NONCE_BYTES);
            $identifier = Identifier::fromBinary($identifier);
            if ($identifier !== self::IDENTIFIER) { // @phpstan-ignore-line will not always evaluate to false
                throw new RuntimeException(sprintf(
                    '%s could not decrypt output of %s',
                    self::IDENTIFIER->name,
                    $identifier->name,
                ));
            }
            return $decrypt($ciphertext, $nonce);
        } catch (Exception\CouldNotDecryptData $exception) {
            throw $exception;
        } catch (Throwable $reason) {
            throw new Exception\CouldNotDecryptData(__METHOD__, $ciphertextWithHeader, $reason);
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
