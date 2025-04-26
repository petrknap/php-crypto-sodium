<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Sign::class)]
final class SignInDetachedModeTest extends SignTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->encryptMethodName = 'signDetached';
        $this->encryptArgsSet = [
            [self::MESSAGE, $this->secretKey],
        ];
        $this->encrypted = base64_decode(self::B64_SIGNATURE);

        $this->decryptMethodName = 'verifyDetached';
        $this->decryptArgsSet = [
            [$this->encrypted, self::MESSAGE, $this->publicKey],
        ];
        $this->decrypted = true;
    }
}
