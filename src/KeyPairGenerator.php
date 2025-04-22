<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

interface KeyPairGenerator
{
    /**
     * @param non-empty-string|null $seedOrSecretKey
     * @param non-empty-string|null $publicKey
     *
     * @throws Exception\CouldNotGenerateKeyPair
     */
    public function generateKeyPair(
        #[SensitiveParameter]
        string|null $seedOrSecretKey = null,
        string|null $publicKey = null,
    ): string; // @todo return KeyPair
}
