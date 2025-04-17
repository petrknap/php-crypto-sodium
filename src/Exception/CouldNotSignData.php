<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium\Exception;

use PetrKnap\Shorts\Exception\CouldNotProcessData;

/**
 * @extends CouldNotProcessData<string>
 */
final class CouldNotSignData extends CouldNotProcessData implements CryptoSodiumException
{
}
