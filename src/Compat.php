<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use ParagonIE\PQCrypto\MLDSA44\SigningKey as MLDSA44SK;
use ParagonIE\PQCrypto\MLDSA44\VerificationKey as MLDSA44VK;
use ParagonIE\PQCrypto\MLDSA44\Signature as MLDSA44Sig;
use ParagonIE\PQCrypto\MLDSA65\SigningKey as MLDSA65SK;
use ParagonIE\PQCrypto\MLDSA65\VerificationKey as MLDSA65VK;
use ParagonIE\PQCrypto\MLDSA65\Signature as MLDSA65Sig;
use ParagonIE\PQCrypto\MLDSA87\SigningKey as MLDSA87SK;
use ParagonIE\PQCrypto\MLDSA87\VerificationKey as MLDSA87VK;
use ParagonIE\PQCrypto\MLDSA87\Signature as MLDSA87Sig;
use ParagonIE\PQCrypto\MLKem512\DecapsulationKey as MLKem512DK;
use ParagonIE\PQCrypto\MLKem512\EncapsulationKey as MLKem512EK;
use ParagonIE\PQCrypto\MLKem768\DecapsulationKey as MLKem768DK;
use ParagonIE\PQCrypto\MLKem768\EncapsulationKey as MLKem768EK;
use ParagonIE\PQCrypto\MLKem1024\DecapsulationKey as MLKem1024DK;
use ParagonIE\PQCrypto\MLKem1024\EncapsulationKey as MLKem1024EK;
use ParagonIE\PQCrypto\XWing\DecapsulationKey as XWingDK;
use ParagonIE\PQCrypto\XWing\EncapsulationKey as XWingEK;
// see ext-crypto for the PQCrypto top-level namespace
use PQCrypto\{
    MLDSA44 as ExtMLDSA44,
    MLDSA44\SigningKey as ExtMLDSA44SK,
    MLDSA44\VerifyingKey as ExtMLDSA44VK,
    MLDSA65 as ExtMLDSA65,
    MLDSA65\SigningKey as ExtMLDSA65SK,
    MLDSA65\VerifyingKey as ExtMLDSA65VK,
    MLDSA87 as ExtMLDSA87,
    MLDSA87\SigningKey as ExtMLDSA87SK,
    MLDSA87\VerifyingKey as ExtMLDSA87VK,
    MLKem512 as ExtMLKem512,
    MLKem512\DecapsulationKey as ExtMLKem512DK,
    MLKem512\EncapsulationKey as ExtMLKem512EK,
    MLKem768 as ExtMLKem768,
    MLKem768\DecapsulationKey as ExtMLKem768DK,
    MLKem768\EncapsulationKey as ExtMLKem768EK,
    XWing as ExtXWing,
    XWing\DecapsulationKey as ExtXWingDK,
    XWing\EncapsulationKey as ExtXWingEK,
    MLKem1024 as ExtMLKem1024,
    MLKem1024\DecapsulationKey as ExtMLKem1024DK,
    MLKem1024\EncapsulationKey as ExtMLKem1024EK,
};
use Random\RandomException;
use SodiumException;

abstract class Compat
{
    /**
     * @return array{0: MLKem512DK, 1: MLKem512EK}
     *
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem512_keygen(): array
    {
        if (self::useExtension()) {
            [$dk, $ek] = ExtMLKem512::generateKeypair();
            return [
                new MLKem512DK($dk->bytes()),
                new MLKem512EK($ek->bytes()),
            ];
        }
        return MLKem512::generateKeypair();
    }

    /**
     * @return array{sharedKey: string, ciphertext: string}
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem512_encaps(
        string|EncapsKeyInterface $ek
    ): array {
        if (self::useExtension()) {
            $extEk = ExtMLKem512EK::fromBytes(
                is_string($ek) ? $ek : $ek->bytes()
            );
            [$ss, $ct] = $extEk->encapsulate();
            return ['sharedKey' => $ss, 'ciphertext' => $ct];
        }
        return MLKem512::encapsulate(
            is_string($ek) ? new MLKem512EK($ek) : $ek
        );
    }

    /**
     * @throws MLKemInternalException
     */
    public static function mlkem512_decaps(
        string|DecapsKeyInterface $dk,
        string $ciphertext
    ): string {
        if (self::useExtension()) {
            $extDk = ExtMLKem512DK::fromBytes(
                is_string($dk) ? $dk : $dk->bytes()
            );
            return $extDk->decapsulate($ciphertext);
        }
        return MLKem512::decapsulate(
            is_string($dk) ? new MLKem512DK($dk) : $dk,
            $ciphertext
        );
    }

    /**
     * @return array{0: MLKem768DK, 1: MLKem768EK}
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem768_keygen(): array
    {
        if (self::useExtension()) {
            [$dk, $ek] = ExtMLKem768::generateKeypair();
            return [
                new MLKem768DK($dk->bytes()),
                new MLKem768EK($ek->bytes()),
            ];
        }
        return MLKem768::generateKeypair();
    }

    /**
     * @return array{sharedKey: string, ciphertext: string}
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem768_encaps(
        string|EncapsKeyInterface $ek
    ): array {
        if (self::useExtension()) {
            $extEk = ExtMLKem768EK::fromBytes(
                is_string($ek) ? $ek : $ek->bytes()
            );
            [$ss, $ct] = $extEk->encapsulate();
            return ['sharedKey' => $ss, 'ciphertext' => $ct];
        }
        return MLKem768::encapsulate(
            is_string($ek) ? new MLKem768EK($ek) : $ek
        );
    }

    /**
     * @throws MLKemInternalException
     */
    public static function mlkem768_decaps(
        string|DecapsKeyInterface $dk,
        string $ciphertext
    ): string {
        if (self::useExtension()) {
            $extDk = ExtMLKem768DK::fromBytes(
                is_string($dk) ? $dk : $dk->bytes()
            );
            return $extDk->decapsulate($ciphertext);
        }
        return MLKem768::decapsulate(
            is_string($dk) ? new MLKem768DK($dk) : $dk,
            $ciphertext
        );
    }

    /**
     * @return array{0: MLKem1024DK, 1: MLKem1024EK}
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem1024_keygen(): array
    {
        if (self::useExtension()) {
            [$dk, $ek] = ExtMLKem1024::generateKeypair();
            return [
                new MLKem1024DK($dk->bytes()),
                new MLKem1024EK($ek->bytes()),
            ];
        }
        return MLKem1024::generateKeypair();
    }

    /**
     * @return array{sharedKey: string, ciphertext: string}
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public static function mlkem1024_encaps(string|EncapsKeyInterface $ek): array
    {
        if (self::useExtension()) {
            $extEk = ExtMLKem1024EK::fromBytes(
                is_string($ek) ? $ek : $ek->bytes()
            );
            [$ss, $ct] = $extEk->encapsulate();
            return ['sharedKey' => $ss, 'ciphertext' => $ct];
        }
        return MLKem1024::encapsulate(
            is_string($ek) ? new MLKem1024EK($ek) : $ek
        );
    }

    /**
     * @throws MLKemInternalException
     */
    public static function mlkem1024_decaps(
        string|DecapsKeyInterface $dk,
        string $ciphertext
    ): string {
        if (self::useExtension()) {
            $extDk = ExtMLKem1024DK::fromBytes(
                is_string($dk) ? $dk : $dk->bytes()
            );
            return $extDk->decapsulate($ciphertext);
        }
        return MLKem1024::decapsulate(
            is_string($dk) ? new MLKem1024DK($dk) : $dk,
            $ciphertext
        );
    }

    /**
     * @return array{signingKey: MLDSA44SK, verificationKey: MLDSA44VK}
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa44_keygen(): array
    {
        if (self::useExtension()) {
            [$sk, $vk] = ExtMLDSA44::generateKeypair();
            return [
                'signingKey' => MLDSA44SK::fromBytes($sk->bytes()),
                'verificationKey' => MLDSA44VK::fromBytes(
                    $vk->bytes()
                ),
            ];
        }
        $sk = MLDSA44SK::fromBytes(random_bytes(32));
        return [
            'signingKey' => $sk,
            'verificationKey' => $sk->getVerificationKey(),
        ];
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa44_sign(
        string|SigningKeyInterface $sk,
        string $message,
        string $ctx = ''
    ): MLDSA44Sig {
        $skBytes = is_string($sk) ? $sk : $sk->bytes();
        if (self::useExtension() && $ctx === '') {
            $extSk = ExtMLDSA44SK::fromBytes($skBytes);
            return MLDSA44Sig::fromBytes($extSk->sign($message));
        }
        $skObj = MLDSA44SK::fromBytes($skBytes);
        return $skObj->sign($message, $ctx);
    }

    /**
     * @throws MLDSAInternalException
     */
    public static function mldsa44_verify(
        string|VerificationKeyInterface $vk,
        SignatureInterface|string $sig,
        string $message,
        string $ctx = ''
    ): bool {
        $vkBytes = is_string($vk) ? $vk : $vk->bytes();
        $sigBytes = is_string($sig) ? $sig : $sig->bytes();
        if (self::useExtension() && $ctx === '') {
            $extVk = ExtMLDSA44VK::fromBytes($vkBytes);
            return $extVk->verify($sigBytes, $message);
        }
        $vkObj = MLDSA44VK::fromBytes($vkBytes);
        $sigObj = MLDSA44Sig::fromBytes($sigBytes);
        return $vkObj->verify($sigObj, $message, $ctx);
    }

    /**
     * @return array{signingKey: MLDSA65SK, verificationKey: MLDSA65VK}
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa65_keygen(): array
    {
        if (self::useExtension()) {
            [$sk, $vk] = ExtMLDSA65::generateKeypair();
            return [
                'signingKey' => MLDSA65SK::fromBytes($sk->bytes()),
                'verificationKey' => MLDSA65VK::fromBytes(
                    $vk->bytes()
                ),
            ];
        }
        $sk = MLDSA65SK::fromBytes(random_bytes(32));
        return [
            'signingKey' => $sk,
            'verificationKey' => $sk->getVerificationKey(),
        ];
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa65_sign(
        string|SigningKeyInterface $sk,
        string $message,
        string $ctx = ''
    ): MLDSA65Sig {
        $skBytes = is_string($sk) ? $sk : $sk->bytes();
        if (self::useExtension() && $ctx === '') {
            $extSk = ExtMLDSA65SK::fromBytes($skBytes);
            return MLDSA65Sig::fromBytes($extSk->sign($message));
        }
        $skObj = MLDSA65SK::fromBytes($skBytes);
        return $skObj->sign($message, $ctx);
    }

    /**
     * @throws MLDSAInternalException
     */
    public static function mldsa65_verify(
        string|VerificationKeyInterface $vk,
        SignatureInterface|string $sig,
        string $message,
        string $ctx = ''
    ): bool {
        $vkBytes = is_string($vk) ? $vk : $vk->bytes();
        $sigBytes = is_string($sig) ? $sig : $sig->bytes();
        if (self::useExtension() && $ctx === '') {
            $extVk = ExtMLDSA65VK::fromBytes($vkBytes);
            return $extVk->verify($sigBytes, $message);
        }
        $vkObj = MLDSA65VK::fromBytes($vkBytes);
        $sigObj = MLDSA65Sig::fromBytes($sigBytes);
        return $vkObj->verify($sigObj, $message, $ctx);
    }

    /**
     * @return array{signingKey: MLDSA87SK, verificationKey: MLDSA87VK}
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa87_keygen(): array
    {
        if (self::useExtension()) {
            [$sk, $vk] = ExtMLDSA87::generateKeypair();
            return [
                'signingKey' => MLDSA87SK::fromBytes($sk->bytes()),
                'verificationKey' => MLDSA87VK::fromBytes(
                    $vk->bytes()
                ),
            ];
        }
        $sk = MLDSA87SK::fromBytes(random_bytes(32));
        return [
            'signingKey' => $sk,
            'verificationKey' => $sk->getVerificationKey(),
        ];
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public static function mldsa87_sign(
        string|SigningKeyInterface $sk,
        string $message,
        string $ctx = ''
    ): MLDSA87Sig {
        $skBytes = is_string($sk) ? $sk : $sk->bytes();
        if (self::useExtension() && $ctx === '') {
            $extSk = ExtMLDSA87SK::fromBytes($skBytes);
            return MLDSA87Sig::fromBytes($extSk->sign($message));
        }
        $skObj = MLDSA87SK::fromBytes($skBytes);
        return $skObj->sign($message, $ctx);
    }

    /**
     * @throws MLDSAInternalException
     */
    public static function mldsa87_verify(
        string|VerificationKeyInterface $vk,
        SignatureInterface|string $sig,
        string $message,
        string $ctx = ''
    ): bool {
        $vkBytes = is_string($vk) ? $vk : $vk->bytes();
        $sigBytes = is_string($sig) ? $sig : $sig->bytes();
        if (self::useExtension() && $ctx === '') {
            $extVk = ExtMLDSA87VK::fromBytes($vkBytes);
            return $extVk->verify($sigBytes, $message);
        }
        $vkObj = MLDSA87VK::fromBytes($vkBytes);
        $sigObj = MLDSA87Sig::fromBytes($sigBytes);
        return $vkObj->verify($sigObj, $message, $ctx);
    }

    /**
     * @return array{0: MLKem768DK, 1: MLKem768EK}
     * @throws MLKemInternalException
     * @throws RandomException
     * @throws SodiumException
     */
    public static function xwing_keygen(): array
    {
        if (self::useExtension()) {
            [$dk, $ek] = ExtXWing::generateKeypair();
            return [
                new XWingDK($dk->bytes()),
                new XWingEK($ek->bytes()),
            ];
        }
        return XWing::generateKeypair();
    }

    /**
     * @return array{sharedKey: string, ciphertext: string}
     *
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public static function xwing_encaps(string|EncapsKeyInterface $ek): array
    {
        if (self::useExtension()) {
            $extEk = ExtXWingEK::fromBytes(is_string($ek) ? $ek : $ek->bytes());
            [$ss, $ct] = $extEk->encapsulate();
            return ['sharedKey' => $ss, 'ciphertext' => $ct];
        }
        return XWing::encapsulate(
            is_string($ek) ? new XWingEK($ek) : $ek
        );
    }

    /**
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public static function xwing_decaps(
        string|DecapsKeyInterface $dk,
        string $ciphertext
    ): string {
        if (self::useExtension()) {
            $extDk = ExtXWingDK::fromBytes(
                is_string($dk) ? $dk : $dk->bytes()
            );
            return $extDk->decapsulate($ciphertext);
        }
        return XWing::decapsulate(
            is_string($dk) ? new XWingDK($dk) : $dk,
            $ciphertext
        );
    }

    private static function useExtension(): bool
    {
        return extension_loaded('pqcrypto');
    }
}
