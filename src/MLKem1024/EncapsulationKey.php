<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\MLKem1024;

use ParagonIE\PQCrypto\EncapsKeyInterface;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\MLKem1024;
use Random\RandomException;

class EncapsulationKey implements EncapsKeyInterface
{
    public function __construct(
        #[SensitiveParameter]
        private string $key
    ) {}

    public function bytes(): string
    {
        return $this->key;
    }

    /**
     * @throws RandomException
     * @throws MLKemInternalException
     */
    public function encapsulate(): array
    {
        return MLKem1024::encapsulate($this);
    }
}
