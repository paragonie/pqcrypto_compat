<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

interface SigningKeyInterface
{
    public function bytes(): string;
    public function sign(string $message, string $ctx = ''): SignatureInterface;
    public function getVerificationKey(): VerificationKeyInterface;
}
