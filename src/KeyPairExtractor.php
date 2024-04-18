<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

interface KeyPairExtractor
{
    /**
     * @throws Exception\CouldNotExtractSecretKey
     */
    public function extractSecretKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string;

    /**
     * @throws Exception\CouldNotExtractPublicKey
     */
    public function extractPublicKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string;
}
