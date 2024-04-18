<?php

declare(strict_types=1);

namespace PetrKnap\CryptoSodium;

use SensitiveParameter;

interface DataEraser
{
    /**
     * @throws Exception\CouldNotEraseData
     */
    public function eraseData(
        #[SensitiveParameter]
        string &$data,
    ): void;
}
