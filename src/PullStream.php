<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

final class PullStream extends Stream
{
    /**
     * @internal there is no reason to call it from the outside
     */
    public function __construct(
        object $instance,
        #[SensitiveParameter]
        string &$state,
        public readonly int $aBytes,
    ) {
        parent::__construct($instance, $state);
    }

    /**
     * @throws Exception\CouldNotDecryptData
     */
    public function pull(string $ciphertext, string|null $additionalData = null): MessageWithTag
    {
        return $this->instance->pull(
            $this,
            ...func_get_args() // @phpstan-ignore-line
        );
    }
}
