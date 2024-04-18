<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

final class SecretBoxTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new SecretBox();

        $key = base64_decode('4ayqwrn6R6uy4oyQyoOnowdosil5ZPPqKtFtCj5WkjQ=');
        $nonce = base64_decode('mXVQMM6ud/69jDTsIGHTuNrktqcCebQR');
        $this->encryptArgs = [self::MESSAGE, $key, $nonce];
        $this->ciphertextWithNonce = SecretBox::IDENTIFIER->toBinary() . $nonce . base64_decode('reUOODrutLarlV3PBYoLmRShxivRqzIJqDJto74=');
        $this->decryptArgs = [$this->ciphertextWithNonce, $key];
    }
}
