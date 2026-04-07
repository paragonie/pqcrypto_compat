<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Traits;

use ParagonIE\PQCrypto\DecapsKeyInterface;
use ParagonIE\PQCrypto\EncapsKeyInterface;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Internal\MLKem\Operations;
use Random\RandomException;
use SensitiveParameter;
use function random_bytes;
use function strlen;
use function substr;

trait MLKemTrait
{
    /**
     * Derandomized key generation (for testing).
     *
     * @param string $d 32-byte seed.
     * @param string $z 32-byte seed.
     * @return array{encapsulationKey: string, decapsulationKey: string}
     *
     * @throws MLKemInternalException
     */
    public static function keyGenInternal(string $d, string $z): array
    {
        if (strlen($d) !== 32 || strlen($z) !== 32) {
            throw new MlKemInternalException('Seeds must be 32 bytes each');
        }
        $key = Operations::kemKeyGen(
            self::K,
            self::ETA1,
            $d,
            $z
        );
        return [
            'encapsulationKey' => $key['encapsulationKeyBytes'],
            'decapsulationKey' => $d . $z,
        ];
    }

    /**
     * @param EncapsKeyInterface $encapsulationKey
     * @return array{sharedKey: string, ciphertext: string}
     *
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function encapsulate(EncapsKeyInterface $encapsulationKey): array
    {
        $keyBytes = $encapsulationKey->bytes();
        if (strlen($keyBytes)
            !== self::ENCAPSULATION_KEY_SIZE
        ) {
            throw new MLKemInternalException('Invalid encapsulation key length');
        }
        $m = random_bytes(32);
        return self::encapsulateInternal($keyBytes, $m);
    }

    /**
     * @param string $encapsulationKey
     * @param string $m
     * @return array{sharedKey: string, ciphertext: string}
     * @throws MLKemInternalException
     */
    public static function encapsulateInternal(
        #[SensitiveParameter]
        string $encapsulationKey,
        #[SensitiveParameter]
        string $m
    ): array {
        if (strlen($encapsulationKey) !== self::ENCAPSULATION_KEY_SIZE) {
            throw new MLKemInternalException('Invalid encapsulation key length');
        }
        $ek = Operations::parseEncapsulationKey(
            self::K,
            $encapsulationKey
        );
        return Operations::kemEncaps(
            self::K,
            self::ETA1,
            self::DU,
            self::DV,
            $ek,
            $m
        );
    }

    /**
     * @param DecapsKeyInterface $decapsulationKey
     * @param string $ciphertext
     * @return string
     *
     * @throws MLKemInternalException
     */
    public static function decapsulate(
        DecapsKeyInterface $decapsulationKey,
        string $ciphertext
    ): string {
        $decapsulationKeyBytes = $decapsulationKey->bytes();
        if (strlen($decapsulationKeyBytes) !== self::SEED_SIZE) {
            throw new MLKemInternalException(
                'Invalid decapsulation key length'
            );
        }
        if (strlen($ciphertext) !== self::CIPHERTEXT_SIZE) {
            throw new MLKemInternalException(
                'Invalid ciphertext length'
            );
        }

        $d = substr($decapsulationKeyBytes, 0, 32);
        $z = substr($decapsulationKeyBytes, 32, 32);

        $key = Operations::kemKeyGen(
            self::K,
            self::ETA1,
            $d,
            $z
        );

        return Operations::kemDecaps(
            self::K,
            self::ETA1,
            self::DU,
            self::DV,
            $z,
            $key['h'],
            ['t' => $key['t'], 'a' => $key['a']],
            $key['s'],
            $ciphertext
        );
    }
}
