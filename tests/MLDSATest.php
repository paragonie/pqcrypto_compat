<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\MLDSA44;
use ParagonIE\PQCrypto\MLDSA44\Signature as Sig44;
use ParagonIE\PQCrypto\MLDSA44\SigningKey as SK44;
use ParagonIE\PQCrypto\MLDSA44\VerificationKey as VK44;
use ParagonIE\PQCrypto\MLDSA65;
use ParagonIE\PQCrypto\MLDSA65\SigningKey as SK65;
use ParagonIE\PQCrypto\MLDSA87;
use ParagonIE\PQCrypto\MLDSA87\SigningKey as SK87;
use ParagonIE\PQCrypto\Internal\MLDSA\Params;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

#[Group("ML-DSA")]
#[CoversClass(MLDSA44::class)]
#[CoversClass(MLDSA65::class)]
#[CoversClass(MLDSA87::class)]
class MLDSATest extends TestCase
{
    public function testMLDSA44Keygen(): void
    {
        $sk = SK44::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $this->assertInstanceOf(SK44::class, $sk);
        $this->assertInstanceOf(VK44::class, $vk);
        $this->assertSame(32, strlen($sk->bytes()));
        $this->assertSame(
            Params::MLDSA44->publicKeySize(),
            strlen($vk->bytes())
        );
    }

    public function testMLDSA44KeySerialization(): void
    {
        $sk = SK44::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $sk2 = SK44::fromBytes($sk->bytes());
        $vk2 = VK44::fromBytes($vk->bytes());

        $this->assertSame($sk->bytes(), $sk2->bytes());
        $this->assertSame($vk->bytes(), $vk2->bytes());
    }

    public function testMLDSA65Keygen(): void
    {
        $sk = SK65::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $this->assertSame(32, strlen($sk->bytes()));
        $this->assertSame(
            Params::MLDSA65->publicKeySize(),
            strlen($vk->bytes())
        );
    }

    public function testMLDSA87Keygen(): void
    {
        $sk = SK87::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $this->assertSame(32, strlen($sk->bytes()));
        $this->assertSame(
            Params::MLDSA87->publicKeySize(),
            strlen($vk->bytes())
        );
    }

    #[Group("Slow")]
    public function testMLDSA44RoundTrip(): void
    {
        $sk = SK44::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $msg = 'Test message for ML-DSA-44';
        $sig = $sk->sign($msg);
        $this->assertInstanceOf(Sig44::class, $sig);
        $this->assertSame(
            Params::MLDSA44->signatureSize(),
            strlen($sig->bytes())
        );

        $this->assertTrue($vk->verify($sig, $msg));
        $this->assertFalse($vk->verify($sig, $msg . '!'));
    }

    #[Group("Slow")]
    public function testMLDSA44SignatureSerialization(): void
    {
        $sk = SK44::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $sig = $sk->sign('Signature serialization');
        $sig2 = Sig44::fromBytes($sig->bytes());
        $this->assertTrue($vk->verify($sig2, 'Signature serialization'));
    }

    #[Group("Slow")]
    public function testMLDSA44WithContext(): void
    {
        $sk = SK44::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $msg = 'Context test';
        $ctx = 'my-app-v1';
        $sig = $sk->sign($msg, $ctx);

        $this->assertTrue($vk->verify($sig, $msg, $ctx));
        $this->assertFalse($vk->verify($sig, $msg));
        $this->assertFalse($vk->verify($sig, $msg, 'wrong-ctx'));
    }

    /**
     * @throws RandomException
     * @throws MLDSAInternalException
     */
    public function testLongContextRejected(): void
    {
        /** @var SK44|SK65|SK87 $skClass */
        foreach ([SK44::class, SK65::class, SK87::class] as $skClass) {
            $sk = $skClass::fromBytes(str_repeat("\x01", 32));
            $vk = $sk->getVerificationKey();
            $message = 'Context collision regression';
            $maxContext = str_repeat('C', 255);
            $this->assertTrue($vk->verify($sk->sign($message, $maxContext), $message, $maxContext));
            foreach ([256, 512] as $length) {
                $ctx = str_repeat('C', $length);
                // Before the fix, this signature also verified as ($message, $ctx).
                $sig = $sk->sign($ctx . $message);
                $this->assertTrue($vk->verify($sig, $ctx . $message));
                try {
                    $vk->verify($sig, $message, $ctx);
                    $this->fail('Verification must reject an overlong context');
                } catch (MLDSAInternalException) {
                    $this->addToAssertionCount(1);
                }
                try {
                    $sk->sign($message, $ctx);
                    $this->fail('Signing must reject an overlong context');
                } catch (MLDSAInternalException) {
                    $this->addToAssertionCount(1);
                }
            }
        }
    }

    #[Group("Slow")]
    public function testMLDSA65RoundTrip(): void
    {
        $sk = SK65::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $msg = 'Test message for ML-DSA-65';
        $sig = $sk->sign($msg);
        $this->assertSame(
            Params::MLDSA65->signatureSize(),
            strlen($sig->bytes())
        );

        $this->assertTrue($vk->verify($sig, $msg));
        $this->assertFalse($vk->verify($sig, $msg . '!'));
    }

    #[Group("Slow")]
    public function testMLDSA87RoundTrip(): void
    {
        $sk = SK87::fromBytes(random_bytes(32));
        $vk = $sk->getVerificationKey();

        $msg = 'Test message for ML-DSA-87';
        $sig = $sk->sign($msg);
        $this->assertSame(
            Params::MLDSA87->signatureSize(),
            strlen($sig->bytes())
        );

        $this->assertTrue($vk->verify($sig, $msg));
        $this->assertFalse($vk->verify($sig, $msg . '!'));
    }
}
