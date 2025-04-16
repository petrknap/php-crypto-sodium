<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

interface KeyPairExtractor
{
    /**
     * @param non-empty-string $keyPair
     *
     * @throws Exception\CouldNotExtractSecretKey
     */
    public function extractSecretKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string; // @todo return Key

    /**
     * @param non-empty-string $keyPair
     *
     * @throws Exception\CouldNotExtractPublicKey
     */
    public function extractPublicKey(
        #[SensitiveParameter]
        string &$keyPair,
    ): string; // @todo return Key
}
