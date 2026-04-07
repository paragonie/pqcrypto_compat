<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\MLDSA65;

use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\MLDSA\InternalSignature;
use ParagonIE\PQCrypto\Internal\MLDSA\Params;
use ParagonIE\PQCrypto\SignatureInterface;

class Signature implements SignatureInterface
{
    const PARAMS = Params::MLDSA65;
    public function __construct(public InternalSignature $sig)
    {}

    public function bytes(): string
    {
        return $this->sig->bytes();
    }

    /**
     * @throws MLDSAInternalException
     */
    public static function fromBytes(string $bytes): self
    {
        return new self(InternalSignature::fromBytes(self::PARAMS, $bytes));
    }
}
