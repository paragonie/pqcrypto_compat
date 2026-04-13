<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use ParagonIE\PQCrypto\MLDSA44\Signature as Sig44;
use ParagonIE\PQCrypto\MLDSA44\SigningKey as SK44;
use ParagonIE\PQCrypto\MLDSA44\VerificationKey as VK44;
use ParagonIE\PQCrypto\MLDSA65\Signature as Sig65;
use ParagonIE\PQCrypto\MLDSA65\SigningKey as SK65;
use ParagonIE\PQCrypto\MLDSA65\VerificationKey as VK65;
use ParagonIE\PQCrypto\MLDSA87\Signature as Sig87;
use ParagonIE\PQCrypto\MLDSA87\SigningKey as SK87;
use ParagonIE\PQCrypto\MLDSA87\VerificationKey as VK87;
use ParagonIE\PQCrypto\MLKem512\DecapsulationKey as MLKem512DK;
use ParagonIE\PQCrypto\MLKem512\EncapsulationKey as MLKem512EK;
use ParagonIE\PQCrypto\MLKem768\DecapsulationKey as MLKem768DK;
use ParagonIE\PQCrypto\MLKem768\EncapsulationKey as MLKem768EK;
use ParagonIE\PQCrypto\MLKem1024\DecapsulationKey as MLKem1024DK;
use ParagonIE\PQCrypto\MLKem1024\EncapsulationKey as MLKem1024EK;
use ParagonIE\PQCrypto\XWing\DecapsulationKey as XWingDK;
use ParagonIE\PQCrypto\XWing\EncapsulationKey as XWingEK;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(Compat::class)]
class CompatTest extends TestCase
{
    public function testMLKem512Compat(): void
    {
        [$dk, $ek] = Compat::mlkem512_keygen();
        $this->assertInstanceOf(MLKem512DK::class, $dk);
        $this->assertInstanceOf(MLKem512EK::class, $ek);

        $result = Compat::mlkem512_encaps($ek);
        $this->assertArrayHasKey('sharedKey', $result);
        $this->assertArrayHasKey('ciphertext', $result);
        $this->assertSame(32, strlen($result['sharedKey']));

        $ss = Compat::mlkem512_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    public function testMLKem512CompatStringKeys(): void
    {
        [$dk, $ek] = Compat::mlkem512_keygen();

        $result = Compat::mlkem512_encaps($ek->bytes());
        $ss = Compat::mlkem512_decaps(
            $dk->bytes(),
            $result['ciphertext']
        );
        $this->assertSame($result['sharedKey'], $ss);
    }

    public function testMLKem768Compat(): void
    {
        [$dk, $ek] = Compat::mlkem768_keygen();
        $this->assertInstanceOf(MLKem768DK::class, $dk);
        $this->assertInstanceOf(MLKem768EK::class, $ek);

        $result = Compat::mlkem768_encaps($ek);
        $ss = Compat::mlkem768_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    public function testXWingCompat(): void
    {
        [$dk, $ek] = Compat::xwing_keygen();
        $this->assertInstanceOf(XWingDK::class, $dk);
        $this->assertInstanceOf(XWingEK::class, $ek);

        $result = Compat::xwing_encaps($ek);
        $ss = Compat::xwing_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    public function testMLKem1024Compat(): void
    {
        [$dk, $ek] = Compat::mlkem1024_keygen();
        $this->assertInstanceOf(MLKem1024DK::class, $dk);
        $this->assertInstanceOf(MLKem1024EK::class, $ek);

        $result = Compat::mlkem1024_encaps($ek);
        $ss = Compat::mlkem1024_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    /**
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLKem512SeedKeypair(): void
    {
        $seed = random_bytes(64);
        [$dk, $ek] = Compat::mlkem512_seed_keypair($seed);
        $this->assertInstanceOf(MLKem512DK::class, $dk);
        $this->assertInstanceOf(MLKem512EK::class, $ek);
        $this->assertSame($seed, $dk->bytes());

        [$dk2, $ek2] = Compat::mlkem512_seed_keypair($seed);
        $this->assertSame($dk->bytes(), $dk2->bytes());
        $this->assertSame($ek->bytes(), $ek2->bytes());

        $result = Compat::mlkem512_encaps($ek);
        $ss = Compat::mlkem512_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);

        $this->expectException(PQCryptoCompatException::class);
        Compat::mlkem512_seed_keypair(random_bytes(32));
    }

    /**
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLKem768SeedKeypair(): void
    {
        $seed = random_bytes(64);
        [$dk, $ek] = Compat::mlkem768_seed_keypair($seed);
        $this->assertInstanceOf(MLKem768DK::class, $dk);
        $this->assertInstanceOf(MLKem768EK::class, $ek);
        $this->assertSame($seed, $dk->bytes());

        [$dk2, $ek2] = Compat::mlkem768_seed_keypair($seed);
        $this->assertSame($ek->bytes(), $ek2->bytes());

        $result = Compat::mlkem768_encaps($ek);
        $ss = Compat::mlkem768_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    /**
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLKem1024SeedKeypair(): void
    {
        $seed = random_bytes(64);
        [$dk, $ek] = Compat::mlkem1024_seed_keypair($seed);
        $this->assertInstanceOf(MLKem1024DK::class, $dk);
        $this->assertInstanceOf(MLKem1024EK::class, $ek);
        $this->assertSame($seed, $dk->bytes());

        [$dk2, $ek2] = Compat::mlkem1024_seed_keypair($seed);
        $this->assertSame($ek->bytes(), $ek2->bytes());

        $result = Compat::mlkem1024_encaps($ek);
        $ss = Compat::mlkem1024_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    /**
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testXWingSeedKeypair(): void
    {
        $seed = random_bytes(32);
        [$dk, $ek] = Compat::xwing_seed_keypair($seed);
        $this->assertInstanceOf(XWingDK::class, $dk);
        $this->assertInstanceOf(XWingEK::class, $ek);
        $this->assertSame($seed, $dk->bytes());

        [$dk2, $ek2] = Compat::xwing_seed_keypair($seed);
        $this->assertSame($ek->bytes(), $ek2->bytes());

        $result = Compat::xwing_encaps($ek);
        $ss = Compat::xwing_decaps($dk, $result['ciphertext']);
        $this->assertSame($result['sharedKey'], $ss);
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public function testMLDSA44CompatKeygen(): void
    {
        $keys = Compat::mldsa44_keygen();
        $this->assertArrayHasKey('signingKey', $keys);
        $this->assertArrayHasKey('verificationKey', $keys);
        $this->assertInstanceOf(SK44::class, $keys['signingKey']);
        $this->assertInstanceOf(VK44::class, $keys['verificationKey']);
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public function testMLDSA65CompatKeygen(): void
    {
        $keys = Compat::mldsa65_keygen();
        $this->assertInstanceOf(SK65::class, $keys['signingKey']);
        $this->assertInstanceOf(VK65::class, $keys['verificationKey']);
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    public function testMLDSA87CompatKeygen(): void
    {
        $keys = Compat::mldsa87_keygen();
        $this->assertInstanceOf(SK87::class, $keys['signingKey']);
        $this->assertInstanceOf(VK87::class, $keys['verificationKey']);
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    #[Group("Slow")]
    public function testMLDSA44CompatSignVerify(): void
    {
        $keys = Compat::mldsa44_keygen();

        $msg = 'Compat ML-DSA-44 test';
        $sig = Compat::mldsa44_sign($keys['signingKey'], $msg);
        $this->assertInstanceOf(Sig44::class, $sig);

        $this->assertTrue(
            Compat::mldsa44_verify(
                $keys['verificationKey'],
                $sig,
                $msg
            )
        );
        $this->assertFalse(
            Compat::mldsa44_verify(
                $keys['verificationKey'],
                $sig,
                $msg . '!'
            )
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    #[Group("Slow")]
    public function testMLDSA44CompatStringKeys(): void
    {
        $keys = Compat::mldsa44_keygen();
        $skBytes = $keys['signingKey']->bytes();
        $vkBytes = $keys['verificationKey']->bytes();

        $msg = 'String key test';
        $sig = Compat::mldsa44_sign($skBytes, $msg);
        $this->assertTrue(
            Compat::mldsa44_verify($vkBytes, $sig->bytes(), $msg)
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    #[Group("Slow")]
    public function testMLDSA65CompatSignVerify(): void
    {
        $keys = Compat::mldsa65_keygen();

        $msg = 'Compat ML-DSA-65 test';
        $sig = Compat::mldsa65_sign($keys['signingKey'], $msg);
        $this->assertInstanceOf(Sig65::class, $sig);
        $this->assertTrue(
            Compat::mldsa65_verify(
                $keys['verificationKey'],
                $sig,
                $msg
            )
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws RandomException
     */
    #[Group("Slow")]
    public function testMLDSA87CompatSignVerify(): void
    {
        $keys = Compat::mldsa87_keygen();

        $msg = 'Compat ML-DSA-87 test';
        $sig = Compat::mldsa87_sign($keys['signingKey'], $msg);
        $this->assertInstanceOf(Sig87::class, $sig);
        $this->assertTrue(
            Compat::mldsa87_verify(
                $keys['verificationKey'],
                $sig,
                $msg
            )
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLDSA44SeedKeypair(): void
    {
        $seed = random_bytes(32);
        $keys = Compat::mldsa44_seed_keypair($seed);
        $this->assertInstanceOf(SK44::class, $keys['signingKey']);
        $this->assertInstanceOf(VK44::class, $keys['verificationKey']);

        $keys2 = Compat::mldsa44_seed_keypair($seed);
        $this->assertSame($keys['verificationKey']->bytes(), $keys2['verificationKey']->bytes());

        // Bad seed length
        $this->expectException(PQCryptoCompatException::class);
        Compat::mldsa44_seed_keypair(random_bytes(64));
    }

    /**
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    #[Group("Slow")]
    public function testMLDSA44SeedKeypairSignVerify(): void
    {
        $seed = random_bytes(32);
        $keys = Compat::mldsa44_seed_keypair($seed);

        $msg = 'Seed keypair ML-DSA-44 test';
        $sig = Compat::mldsa44_sign($keys['signingKey'], $msg);
        $this->assertTrue(
            Compat::mldsa44_verify(
                $keys['verificationKey'],
                $sig,
                $msg
            )
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLDSA65SeedKeypair(): void
    {
        $seed = random_bytes(32);
        $keys = Compat::mldsa65_seed_keypair($seed);
        $this->assertInstanceOf(SK65::class, $keys['signingKey']);
        $this->assertInstanceOf(VK65::class, $keys['verificationKey']);

        $keys2 = Compat::mldsa65_seed_keypair($seed);
        $this->assertSame(
            $keys['verificationKey']->bytes(),
            $keys2['verificationKey']->bytes()
        );
    }

    /**
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     */
    public function testMLDSA87SeedKeypair(): void
    {
        $seed = random_bytes(32);
        $keys = Compat::mldsa87_seed_keypair($seed);
        $this->assertInstanceOf(SK87::class, $keys['signingKey']);
        $this->assertInstanceOf(VK87::class, $keys['verificationKey']);

        $keys2 = Compat::mldsa87_seed_keypair($seed);
        $this->assertSame(
            $keys['verificationKey']->bytes(),
            $keys2['verificationKey']->bytes()
        );
    }
}
