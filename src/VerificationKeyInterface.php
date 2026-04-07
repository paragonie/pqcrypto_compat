<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

interface VerificationKeyInterface
{
    public function bytes(): string;
    public function verify(SignatureInterface $signature, string $message, string $ctx = ''): bool;
}
