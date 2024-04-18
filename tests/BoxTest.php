<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

final class BoxTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new Box();

        $keyPair = $this->instance->generateKeyPair(base64_decode('o8DJ9Tp7MT0nOjzzpnrjNQswHHJgwVKrtGgzwWlflaM='));
        $nonce = base64_decode('mXVQMM6ud/69jDTsIGHTuNrktqcCebQR');
        $this->encryptArgs = [self::MESSAGE, $keyPair, $nonce];
        $this->ciphertextWithNonce = base64_decode('AZl1UDDOrnf+vYw07CBh07ja5LanAnm0EQffOOZDlD/HdZJPW0AVq7we7ppK4F+6YIyLFzW9');
        $this->decryptArgs = [$this->ciphertextWithNonce, $keyPair];
    }

    public function testKeyPairGeneratorThrowsOnWrongSeed(): void
    {
        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong seed');
    }

    public function testKeyPairGeneratorThrowsOnWrongKeys(): void
    {
        self::expectException(Exception\CouldNotGenerateKeyPair::class);

        $this->instance->generateKeyPair('wrong secret key', 'wrong public key');
    }
}
