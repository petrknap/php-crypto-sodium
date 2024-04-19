<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\Byter;
use Stringable;

final class CiphertextWithNonce implements Stringable
{
    public function __construct(
        public readonly string $ciphertext,
        public readonly string $nonce,
    ) {
    }

    /**
     * @internal there is no reason to call it from the outside
     */
    public static function fromString(string $ciphertext, int $nonceBytes): self
    {
        [$nonce, $ciphertext] = (new Byter())->bite($ciphertext, $nonceBytes);
        return new self(
            ciphertext: $ciphertext,
            nonce: $nonce,
        );
    }

    public function toString(): string
    {
        return (new Byter())->unbite($this->nonce, $this->ciphertext);
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
