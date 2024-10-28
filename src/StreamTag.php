<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PetrKnap\Shorts\Exception\NotImplemented;
use PetrKnap\Shorts\HasRequirements;

enum StreamTag
{
    use HasRequirements {
        HasRequirements::checkRequirements as _checkRequirements;
    }

    case Message;
    /**
     * @link https://doc.libsodium.org/secret-key_cryptography/secretstream#rekeying
     */
    case ReKey;
    case Push;
    case Final;

    private const ALGO_CONSTANT_TAG_MAP = [
        SecretStream\XChaCha20Poly1305::class => [
            'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE' => self::Message,
            'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY' => self::ReKey,
            'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH' => self::Push,
            'SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL' => self::Final,
        ],
    ];

    /**
     * @internal
     *
     * @param class-string $algo
     */
    public static function checkRequirements(string $algo): void
    {
        self::_checkRequirements(constants: array_keys(self::ALGO_CONSTANT_TAG_MAP[$algo] ?? []));
    }

    /**
     * @internal
     *
     * @param class-string $algo
     */
    public static function default(string $algo): self
    {
        return match ($algo) {
            SecretStream\XChaCha20Poly1305::class => self::Message,
            default => NotImplemented::throw("Default tag for `{$algo}`"),
        };
    }

    /**
     * @internal
     *
     * @param class-string $algo
     */
    public static function fromValue(string $algo, int $tagValue): self
    {
        foreach (self::ALGO_CONSTANT_TAG_MAP[$algo] ?? [] as $constant => $tag) {
            if (constant($constant) === $tagValue) {
                return $tag;
            }
        }
        NotImplemented::throw("Tag with value `{$tagValue}` for `{$algo}`");
    }

    /**
     * @internal
     *
     * @param class-string $algo
     */
    public function toValue(string $algo): int
    {
        foreach (self::ALGO_CONSTANT_TAG_MAP[$algo] ?? [] as $constant => $tag) {
            if ($this === $tag) {
                return constant($constant);
            }
        }
        NotImplemented::throw("Tag `{$this->name}` for `{$algo}`");
    }
}
