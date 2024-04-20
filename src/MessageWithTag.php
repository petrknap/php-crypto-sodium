<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use Stringable;

final class MessageWithTag implements Stringable
{
    public function __construct(
        public readonly string $message,
        public readonly int $tag,
    ) {
    }

    public function toString(): string
    {
        return $this->message;
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
