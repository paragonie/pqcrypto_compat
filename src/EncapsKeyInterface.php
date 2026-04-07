<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

interface EncapsKeyInterface
{
    public function bytes(): string;

    public function encapsulate(): array;
}
