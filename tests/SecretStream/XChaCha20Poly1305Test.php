<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\SecretStream;

use PetrKnap\CryptoSodium\CryptoSodiumTestCase;
use PetrKnap\CryptoSodium\MessageWithTag;
use PetrKnap\CryptoSodium\StreamTag;

final class XChaCha20Poly1305Test extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new XChaCha20Poly1305();
        $additionalData = random_bytes(1);
        $this->pushArgsSet = [
            [self::MESSAGE, null, null],
            [self::MESSAGE, StreamTag::Push, null],
            [self::MESSAGE, null, $additionalData],
            [self::MESSAGE, StreamTag::Push, $additionalData],
            [new MessageWithTag(self::MESSAGE, StreamTag::Push), null, $additionalData],
            [new MessageWithTag(random_bytes(4096), StreamTag::Message)],
            [new MessageWithTag(random_bytes(4096), StreamTag::ReKey)],
            [new MessageWithTag(random_bytes(4096), StreamTag::Final)],
        ];
    }
}
