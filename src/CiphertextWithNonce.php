<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\BinariableInterface;
use PetrKnap\Binary\BinariableTrait;
use PetrKnap\Binary\Byter;

final class CiphertextWithNonce implements BinariableInterface
{
    use BinariableTrait;

    public function __construct(
        public readonly string $ciphertext,
        public readonly string $nonce,
    ) {
    }

    /**
     * @internal there is no reason to call it from the outside
     */
    public static function fromBinary(string $ciphertext, int $nonceBytes): self
    {
        [$nonce, $ciphertext] = (new Byter())->bite($ciphertext, $nonceBytes);
        return new self(
            ciphertext: $ciphertext,
            nonce: $nonce,
        );
    }

    public function toBinary(): string
    {
        return (new Byter())->unbite($this->nonce, $this->ciphertext);
    }

    /**
     * @deprecated use {@see self::toBinary()}
     */
    public function toString(): string
    {
        return $this->toBinary();
    }
}
