<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

interface DecapsKeyInterface
{
    public function bytes(): string;

    public function decapsulate(string $ciphertext): string;
}
