<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Exception;

use PetrKnap\Shorts\ExceptionWrapper;
use RuntimeException;

final class CouldNotExtractPublicKey extends RuntimeException implements KeyPairExtractorException
{
    use ExceptionWrapper;
}
