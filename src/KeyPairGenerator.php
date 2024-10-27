<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

interface KeyPairGenerator
{
    /**
     * @throws Exception\CouldNotGenerateKeyPair
     */
    public function generateKeyPair(
        #[SensitiveParameter]
        string|null $seedOrSecretKey = null,
        string|null $publicKey = null,
    ): string;
}
