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
        ?string $seedOrSecretKey = null,
        ?string $publicKey = null,
    ): string;
}
