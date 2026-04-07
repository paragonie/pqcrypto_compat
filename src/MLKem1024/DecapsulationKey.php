<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\MLKem1024;

use ParagonIE\PQCrypto\DecapsKeyInterface;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\MLKem1024;
use SensitiveParameter;

class DecapsulationKey implements DecapsKeyInterface
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
     * @throws MLKemInternalException
     */
    public function decapsulate(string $ciphertext): string
    {
        return MLKem1024::decapsulate($this, $ciphertext);
    }
}
