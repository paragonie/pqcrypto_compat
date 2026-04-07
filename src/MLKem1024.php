<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Traits\MLKemTrait;
use ParagonIE\PQCrypto\MLKem1024\DecapsulationKey;
use ParagonIE\PQCrypto\MLKem1024\EncapsulationKey;
use Random\RandomException;

abstract class MLKem1024
{
    use MLKemTrait;

    /**
     * Generate a keypair.
     *
     * @return array{0: DecapsulationKey, 1: EncapsulationKey}
     *
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function generateKeypair(): array
    {
        $d = random_bytes(32);
        $z = random_bytes(32);
        $pieces = self::keyGenInternal($d, $z);
        return [
            new DecapsulationKey($pieces['decapsulationKey']),
            new EncapsulationKey($pieces['encapsulationKey']),
        ];
    }

    public const SEED_SIZE = 64;
    public const ENCAPSULATION_KEY_SIZE = 1568;
    public const CIPHERTEXT_SIZE = 1568;
    private const K = 4;
    private const ETA1 = 2;
    private const DU = 11;
    private const DV = 5;
}
