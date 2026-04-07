<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

interface SignatureInterface
{
    public function bytes(): string;
}
