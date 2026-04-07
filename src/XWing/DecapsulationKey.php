<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\XWing;

use ParagonIE\PQCrypto\DecapsKeyInterface;
use ParagonIE\PQCrypto\XWing;
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

    public function decapsulate(string $ciphertext): string
    {
        return XWing::decapsulate($this, $ciphertext);
    }
}
