<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

/**
 * @internal values are in hexadecimal
 */
enum Identifier: string
{
    public const BYTES = 1;

    case SecretBoxGen1 = '00';

    public function toBinary(): string
    {
        /** @var string */
        return hex2bin($this->value);
    }

    public static function fromBinary(string $binary): self
    {
        return self::from(bin2hex($binary));
    }
}
