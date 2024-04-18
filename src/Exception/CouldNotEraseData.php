<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Exception;

use RuntimeException;
use Throwable;

final class CouldNotEraseData extends RuntimeException implements DataEraserException
{
    public function __construct(Throwable $reason)
    {
        parent::__construct($reason->getMessage(), previous: $reason);
    }
}
