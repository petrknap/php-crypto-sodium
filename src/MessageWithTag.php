<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\BinariableInterface;
use PetrKnap\Binary\BinariableTrait;

final class MessageWithTag implements BinariableInterface
{
    use BinariableTrait;

    public function __construct(
        public readonly string $message,
        public readonly int $tag,
    ) {
    }

    public function toBinary(): string
    {
        return $this->message;
    }

    /**
     * @deprecated use {@see self::toBinary()}
     */
    public function toString(): string
    {
        return $this->toBinary();
    }
}
