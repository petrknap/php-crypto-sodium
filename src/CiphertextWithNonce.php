<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Binary\BinariableInterface;
use PetrKnap\Binary\BinariableTrait;
use PetrKnap\Binary\Byter;
use PetrKnap\Binary\Serializer\SelfSerializerInterface;
use PetrKnap\Binary\Serializer\SelfSerializerTrait;

final class CiphertextWithNonce implements BinariableInterface, SelfSerializerInterface
{
    use BinariableTrait;
    use SelfSerializerTrait;

    public function __construct(
        public readonly string $ciphertext,
        public readonly string $nonce,
    ) {
        $this->referencesToConstructorArgs = [
            $this->ciphertext,
            $this->nonce,
        ];
    }

    /**
     * @internal there is no reason to call it from the outside
     *
     * @deprecated use {@see self::fromBinary()}
     */
    public static function fromOldBinary(string $ciphertextWithNonce, int $nonceBytes): self
    {
        [$nonce, $ciphertext] = (new Byter())->bite($ciphertextWithNonce, $nonceBytes);
        return new self(
            ciphertext: $ciphertext,
            nonce: $nonce,
        );
    }

    /**
     * @deprecated use {@see self::toBinary()}
     */
    public function toString(): string
    {
        return $this->toBinary();
    }
}
