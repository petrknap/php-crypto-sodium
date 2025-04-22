<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Sign::class)]
final class SignInCombinedModeTest extends SignTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->encryptMethodName = 'sign';
        $this->encryptArgsSet = [
            [self::MESSAGE, $this->secretKey],
        ];
        $this->encrypted = base64_decode(self::B64_SIGNATURE) . self::MESSAGE;

        $this->decryptMethodName = 'verified';
        $this->decryptArgsSet = [
            [$this->encrypted, $this->publicKey],
        ];
    }
}
