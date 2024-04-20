<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\SecretStream;

use PetrKnap\CryptoSodium\CryptoSodiumTestCase;
use PetrKnap\CryptoSodium\MessageWithTag;

final class XChaCha20Poly1305Test extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new XChaCha20Poly1305();
        $additionalData = random_bytes(1);
        $this->pushArgsSet = [
            [self::MESSAGE, null, null],
            [self::MESSAGE, XChaCha20Poly1305::TAG_PUSH, null],
            [self::MESSAGE, null, $additionalData],
            [self::MESSAGE, XChaCha20Poly1305::TAG_PUSH, $additionalData],
            [new MessageWithTag(self::MESSAGE, XChaCha20Poly1305::TAG_PUSH), null, $additionalData],
            [new MessageWithTag(random_bytes(4096), XChaCha20Poly1305::TAG_MESSAGE)],
            [new MessageWithTag(random_bytes(4096), XChaCha20Poly1305::TAG_REKEY)],
            [new MessageWithTag(random_bytes(4096), XChaCha20Poly1305::TAG_FINAL)],
        ];
    }
}
