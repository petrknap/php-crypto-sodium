<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

interface KeyGenerator
{
    public function generateKey(): string; // @todo return Key
}
