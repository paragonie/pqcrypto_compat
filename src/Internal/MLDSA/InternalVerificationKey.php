<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ParagonIE\PQCrypto\Attributes\Internal;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\SignatureInterface;
use ParagonIE\PQCrypto\Util;

#[Internal]
class InternalVerificationKey
{
    /**
     * @param Params $params
     * @param string $rho
     * @param Ring[] $t1
     */
    public function __construct(
        public Params $params,
        public string $rho,
        public array $t1,
    ) {}

    public function bytes(): string
    {
        $pk = $this->rho;
        $k = $this->params->k();
        for ($i = 0; $i < $k; ++$i) {
            $packed = Operations::simpleBitPack(
                $this->t1[$i]->symmetric(),
                10
            );
            $pk .= Util::byteArrayToString($packed);
        }
        return $pk;
    }

    /**
     * @throws MLDSAInternalException
     */
    public static function fromBytes(Params $params, string $pk): self
    {
        if (strlen($pk) !== $params->publicKeySize()) {
            throw new MLDSAInternalException('invalid public key size');
        }
        $k = $params->k();
        $rho = substr($pk, 0, 32);
        $z = substr($pk, 32);

        $t1 = [];
        $len = 320;
        for ($i = 0; $i < $k; ++$i) {
            $t1[$i] = Operations::simpleBitUnpack(
                Util::stringToByteArray(substr($z, 0, $len)),
                10
            )->symmetric();
            $z = substr($z, $len);
        }
        return new InternalVerificationKey($params, $rho, $t1);
    }

    public function verifyInternal(InternalSignature $signature, string $Mprime): bool
    {
        $Ahat = Operations::expandA($this->params, $this->rho);
        $tr = Operations::H($this->bytes(), 64);
        $mu = Operations::H($tr . $Mprime, 64);

        $c = Operations::sampleInBall($this->params, $signature->c_tilde);

        $z_hat = Operations::nttVec(Operations::ringVectorFromSymmetric($signature->z));
        $c_hat = Operations::ntt(Ring::fromSymmetric($c));

        $t1_2d = Operations::scalarVectorMul(1 << 13, $this->t1);
        $t1_2d_hat = Operations::nttVec($t1_2d);
        $ct1_2d_hat = Operations::scalarVectorNtt($c_hat, $t1_2d_hat);
        $Az_hat = Operations::matrixVectorNtt($this->params, $Ahat, $z_hat);

        $w_approx = Operations::invNttVec(Operations::subVector($Az_hat, $ct1_2d_hat));
        $w1 = Operations::useHintVec($this->params, $signature->h, $w_approx);
        $w1_encoded = Operations::w1Encode($this->params, $w1);

        $c_tilde_prime = Operations::H($mu . $w1_encoded, $this->params->lambda() >> 2);

        $z_inf = Operations::infinityNormVec(Operations::ringVectorFromSymmetric($signature->z));
        $bound = (1 << $this->params->logGamma1()) - $this->params->beta();

        return $z_inf < $bound && hash_equals($signature->c_tilde, $c_tilde_prime);
    }
}
