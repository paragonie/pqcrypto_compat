<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ParagonIE\PQCrypto\SignatureInterface;
use ParagonIE\PQCrypto\Util;

class InternalSignature implements SignatureInterface
{
    /**
     * @param Params $params
     * @param string $c_tilde
     * @param Ring[] $z
     * @param Ring[] $h
     */
    public function __construct(
        public Params $params,
        public string $c_tilde,
        public array $z,
        public array $h
    ) {}

    /**
     * FIPS 204, Algorithm 26
     */
    public function bytes(): string
    {
        $sig = $this->c_tilde;
        $logGamma1 = $this->params->logGamma1();
        $l = $this->params->l();
        for ($i = 0; $i < $l; ++$i) {
            $packed = Operations::bitPack($this->z[$i]->symmetric(), $logGamma1);
            $sig .= Util::byteArrayToString($packed);
        }
        $packed = Operations::hintBitPack($this->params, $this->h);
        $sig .= Util::byteArrayToString($packed);
        return $sig;
    }

    /**
     * FIPS 204, Algorithm 27
     */
    public static function fromBytes(Params $params, string $encoded): self
    {
        if (strlen($encoded) !== $params->signatureSize()) {
            throw new \ParagonIE\PQCrypto\Exception\MLDSAInternalException(
                'Invalid signature length'
            );
        }
        $sig = $encoded;
        $logGamma1 = $params->logGamma1();
        $l = $params->l();
        $lambda_4 = $params->lambda() >> 2;
        $c_tilde = substr($sig, 0, $lambda_4);
        $sig = substr($sig, $lambda_4);
        $len = ($logGamma1 + 1) << 5;
        $z = [];
        for ($i = 0; $i < $l; ++$i) {
            $x_i = Util::stringToByteArray(substr($sig, 0, $len));
            $sig = substr($sig, $len);
            $z[$i] = Operations::bitUnpack($x_i, $logGamma1);
        }
        $h = Operations::hintBitUnpack($params, Util::stringToByteArray($sig));
        return new self($params, $c_tilde, $z, $h);
    }
}
