<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;
use Stringable;

final class PushStream extends Stream implements Stringable
{
    /**
     * @internal there is no reason to call it from the outside
     */
    public function __construct(
        object $instance,
        #[SensitiveParameter]
        string &$state,
        public readonly string $header,
    ) {
        parent::__construct($instance, $state);
    }

    /**
     * @throws Exception\CouldNotEncryptData
     */
    public function push(MessageWithTag|string $message, ?int $tag = null, ?string $additionalData = null): string
    {
        return $this->instance->push(
            $this,
            ...func_get_args() // @phpstan-ignore-line
        );
    }

    public function toString(): string
    {
        return $this->header;
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
