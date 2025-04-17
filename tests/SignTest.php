<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

final class SignTest extends CryptoSodiumTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->instance = new Sign();
        $keyPair = $this->instance->generateKeyPair(base64_decode('o8DJ9Tp7MT0nOjzzpnrjNQswHHJgwVKrtGgzwWlflaM='));
        $privateKey = $this->instance->extractSecretKey($keyPair);
        $publicKey = $this->instance->extractPublicKey($keyPair);
        $this->ciphertextWithNonce = new CiphertextWithNonce(
            ciphertext: base64_decode('j/qWk5VmO+HXzH/cuMtw+H1MeT7Mn/w9l2qzqt8tUwnl/QShC5zMG7tDVABANrZbMij+xfRNTZ2AWXaRLX9KDw==') . self::MESSAGE,
            nonce: '',
        );
        $this->encryptMethodName = 'sign';
        $this->encryptArgsSet = [
            [self::MESSAGE, $privateKey],
        ];
        $this->decryptMethodName = 'verified';
        $this->decryptArgsSet = [
            [$this->ciphertextWithNonce->ciphertext, $publicKey],
        ];
    }
}
