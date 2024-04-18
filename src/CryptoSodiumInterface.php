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
     * @return string ciphertext with header
     *
     * @throws Exception\CouldNotEncryptData
     */
    public function encrypt(
        string $message,
        #[SensitiveParameter]
        string &$_,
    ): string;

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function decrypt(
        string $ciphertextWithHeader,
        #[SensitiveParameter]
        string &$_,
    ): string;
}
