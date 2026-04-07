<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\XWing;

use ParagonIE\PQCrypto\EncapsKeyInterface;
use ParagonIE\PQCrypto\XWing;

class EncapsulationKey implements EncapsKeyInterface
{
    public function __construct(private string $key) {}

    public function bytes(): string
    {
        return $this->key;
    }

    public function encapsulate(): array
    {
        return XWing::encapsulate($this);
    }
}
