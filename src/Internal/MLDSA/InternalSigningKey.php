<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ParagonIE\PQCrypto\Attributes\Internal;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\Keccak;
use ParagonIE\PQCrypto\SignatureInterface;
use ParagonIE\PQCrypto\Util;
use SensitiveParameter;

#[Internal]
class InternalSigningKey
{
    /**
     * @param Params $params
     * @param string $rho
     * @param string $K
     * @param string $tr
     * @param Ntt[] $s1hat
     * @param Ntt[] $s2hat
     * @param array $t0hat
     * @param InternalVerificationKey $vk
     * @param Ntt[][] $Ahat Cached expansion of rho
     */
    public function __construct(
        public Params $params,
        #[SensitiveParameter]
        private string $seed,
        #[SensitiveParameter]
        public string $rho,
        #[SensitiveParameter]
        public string $K,
        public string $tr,
        public array $s1hat,
        public array $s2hat,
        public array $t0hat,
        public InternalVerificationKey $vk,
        public array $Ahat,
    ) {}

    /**
     * We do NOT support semi-expanded secret keys.
     */
    public function bytes(): string
    {
        return $this->seed;
    }

    /**
     * FIPS 204, Algorithm 6
     */
    public static function keyGenInternal(Params $params, string $seed): InternalSigningKey
    {
        $s = Operations::H(
            $seed . pack('C', $params->k()) . pack('C', $params->l()),
            128
        );
        $rho = substr($s, 0, 32);
        $rhoPrime = substr($s, 32, 64);
        $K = substr($s, 96, 32);

        $A_hat = Operations::expandA($params, $rho);
        /**
         * @var Ring[] $s1
         * @var Ring[] $s2
         */
        [$s1, $s2] = Operations::expandS($params, $rhoPrime);
        $s1hat = Operations::nttVec($s1);
        $s2hat = Operations::nttVec($s2);
        $tmp = Operations::invNttVec(
            Operations::matrixVectorNtt($params, $A_hat, $s1hat)
        );
        /**
         * @var Ring[] $t1
         * @var Ring[] $t0
         */
        [$t1, $t0] = Operations::power2roundVec(Operations::addVector($tmp, $s2));
        $pk = Operations::pkEncode($params, $rho, $t1);
        $tr = Operations::H($pk, 64);
        $vk = new InternalVerificationKey($params, $rho, $t1);
        $t0hat = Operations::nttVec(Operations::ringVectorFromSymmetric($t0));
        return new InternalSigningKey($params, $seed, $rho, $K, $tr, $s1hat, $s2hat, $t0hat, $vk, $A_hat);
    }

    /**
     * FIPS 204, Algorithm 7
     *
     * @throws MLDSAInternalException
     */
    public function signInternal(string $mPrime, string $rnd): InternalSignature
    {
        // Ahat, s1, s2, and t0 are cached in the NTT domain
        $Ahat = $this->Ahat;
        $l = $this->params->l();
        $mu = Operations::H($this->tr . $mPrime, 64);
        $rhoPrimePrime = Operations::H($this->K . $rnd . $mu, 64);
        $kappa = 0;
        $h = null;

        // Let's calculate these only once:
        $lambda = $this->params->lambda();
        $gamma1_beta = (1 << $this->params->logGamma1()) - $this->params->beta();
        $gamma2_beta = $this->params->gamma2() - $this->params->beta();
        $gamma2 = $this->params->gamma2();

        // Rejection sampling loop
        do {
            $y = Operations::ringVectorFromSymmetric(
                Operations::expandMask($this->params, $rhoPrimePrime, $kappa)
            );
            $kappa += $l;
            $w = Operations::invNttVec(
                Operations::matrixVectorNtt($this->params, $Ahat, Operations::nttVec($y))
            );
            $w1 = Operations::highBitsVec($this->params, $w);
            $w1encoded = Operations::w1Encode($this->params, $w1);
            $c_tilde = Operations::H($mu . $w1encoded, $lambda >> 2);
            $c = Operations::sampleInBall($this->params, $c_tilde);
            $c_hat = Operations::ntt(Ring::fromSymmetric($c));

            $cs1 = Operations::invNttVec(Operations::scalarVectorNtt($c_hat, $this->s1hat));
            $cs2 = Operations::invNttVec(Operations::scalarVectorNtt($c_hat, $this->s2hat));
            $z = Operations::addVector($y, $cs1);

            $r0 = Operations::lowBitsVec($this->params, Operations::subVector($w, $cs2));

            // Rejection sampling:
            $z_inf = Operations::infinityNormVec($z);
            $r0_inf = Operations::infinityNormVec(Operations::ringVectorFromSymmetric($r0));
            if ($z_inf >= $gamma1_beta || $r0_inf >= $gamma2_beta) {
                $z = null;
                $h = null;
                continue;
            }

            $ct0 = Operations::invNttVec(Operations::scalarVectorNtt($c_hat, $this->t0hat));
            $minus_ct0 = Operations::negateVector($ct0);
            $w_cs2_ct0 = Operations::addVector(Operations::subVector($w, $cs2), $ct0);
            $ct0_inf = Operations::infinityNormVec($ct0);
            $h = Operations::makeHintVec($this->params, $minus_ct0, $w_cs2_ct0);
            if ($ct0_inf >= $gamma2) {
                $z = null;
                $h = null;
            }
        } while (is_null($z) || is_null($h));

        // We have a valid signature:
        return new InternalSignature($this->params, $c_tilde, $z, $h);
    }
}
