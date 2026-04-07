<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\MLKem512\DecapsulationKey;
use ParagonIE\PQCrypto\MLKem512\EncapsulationKey;
use ParagonIE\PQCrypto\Traits\MLKemTrait;
use Random\RandomException;

abstract class MLKem512
{
    use MLKemTrait;

    /**
     * Generate a keypair.
     **
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
    public const ENCAPSULATION_KEY_SIZE = 800;
    public const CIPHERTEXT_SIZE = 768;
    private const K = 2;
    private const ETA1 = 3;
    private const DU = 10;
    private const DV = 4;
}
