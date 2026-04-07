<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

use ParagonIE\PQCrypto\Internal\MLDSA\Params;
use ParagonIE\PQCrypto\MLDSA87\SigningKey;
use ParagonIE\PQCrypto\MLDSA87\VerificationKey;
use ParagonIE\PQCrypto\Traits\MLDSATrait;
use Random\RandomException;

class MLDSA87
{
    use MLDSATrait;

    public function getParams(): Params
    {
        return Params::MLDSA87;
    }

    /**
     * @param string $seed
     * @return array{signingKey: SigningKey, verificationKey: VerificationKey}
     */
    public function keyFromSeed(string $seed): array
    {
        $sk = SigningKey::fromBytes($seed);
        return [
            'signingKey' => $sk,
            'verificationKey' => $sk->getVerificationKey(),
        ];
    }

    /**
     * @return array{signingKey: SigningKey, verificationKey: VerificationKey}
     * @throws RandomException
     */
    public function keyGen(): array
    {
        return $this->keyFromSeed(random_bytes(32));
    }
}
