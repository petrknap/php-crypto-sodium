<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Exception;

use PetrKnap\Shorts\ExceptionWrapper;
use RuntimeException;

final class CouldNotEraseData extends RuntimeException implements DataEraserException
{
    use ExceptionWrapper;
}
