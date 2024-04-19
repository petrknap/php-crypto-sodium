<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

abstract class Stream
{
    /**
     * @param CryptoSodiumInterface $instance
     */
    protected function __construct(
        protected readonly object $instance,
        #[SensitiveParameter]
        public string &$state,
    ) {
    }

    /**
     * @throws Exception\CouldNotRekey
     */
    public function rekey(): void
    {
        $this->instance->rekey($this);
    }
}
