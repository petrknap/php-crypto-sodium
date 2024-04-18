<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Exception;

use PetrKnap\Shorts\ExceptionWrapper;
use RuntimeException;

final class CouldNotGenerateKeyPair extends RuntimeException implements KeyPairGeneratorException
{
    use ExceptionWrapper;
}
