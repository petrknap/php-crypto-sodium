<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

abstract class SignTestCase extends CryptoSodiumTestCase
{
    protected const B64_SIGNATURE = 'j/qWk5VmO+HXzH/cuMtw+H1MeT7Mn/w9l2qzqt8tUwnl/QShC5zMG7tDVABANrZbMij+xfRNTZ2AWXaRLX9KDw==';

    protected string $secretKey;
    protected string $publicKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = new Sign();
        $keyPair = $this->instance->generateKeyPair(base64_decode('o8DJ9Tp7MT0nOjzzpnrjNQswHHJgwVKrtGgzwWlflaM='));
        $this->secretKey = $this->instance->extractSecretKey($keyPair);
        $this->publicKey = $this->instance->extractPublicKey($keyPair);
    }
}
