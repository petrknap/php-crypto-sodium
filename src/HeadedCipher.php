<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

interface HeadedCipher
{
    /**
     * @return int bytes
     */
    public function getHeaderSize(): int;
}
