<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\MLDSA\InternalSigningKey;
use ParagonIE\PQCrypto\Internal\MLDSA\Operations;
use ParagonIE\PQCrypto\Internal\MLDSA\Params;
use ParagonIE\PQCrypto\MLDSA44;
use ParagonIE\PQCrypto\MLDSA44\Signature as Signature44;
use ParagonIE\PQCrypto\MLDSA44\VerificationKey as VerificationKey44;
use ParagonIE\PQCrypto\MLDSA65;
use ParagonIE\PQCrypto\MLDSA65\Signature as Signature65;
use ParagonIE\PQCrypto\MLDSA65\VerificationKey as VerificationKey65;
use ParagonIE\PQCrypto\MLDSA87;
use ParagonIE\PQCrypto\MLDSA87\Signature as Signature87;
use ParagonIE\PQCrypto\MLDSA87\VerificationKey as VerificationKey87;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use TrailOfBits\Wycheproof\Provider\GenericProvider;

#[Group("ML-DSA")]
#[Group("Wycheproof")]
#[CoversClass(MLDSA44::class)]
#[CoversClass(MLDSA65::class)]
#[CoversClass(MLDSA87::class)]
class MLDSAWycheproofTest extends TestCase
{
    public static function mldsa44VerifyProvider(): array
    {
        return self::loadVerifyTests('mldsa_44_verify');
    }

    public static function mldsa65VerifyProvider(): array
    {
        return self::loadVerifyTests('mldsa_65_verify');
    }

    public static function mldsa87VerifyProvider(): array
    {
        return self::loadVerifyTests('mldsa_87_verify');
    }

    public static function mldsa44SignSeedProvider(): array
    {
        return self::loadSignSeedTests('mldsa_44_sign_seed');
    }

    public static function mldsa65SignSeedProvider(): array
    {
        return self::loadSignSeedTests('mldsa_65_sign_seed');
    }

    public static function mldsa87SignSeedProvider(): array
    {
        return self::loadSignSeedTests('mldsa_87_sign_seed');
    }

    #[DataProvider('mldsa44VerifyProvider')]
    public function testMldsa44Verify(
        int $tcId,
        string $publicKey,
        string $msg,
        string $sig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
    ): void {
        $this->runVerifyTest(
            VerificationKey44::class,
            Signature44::class,
            $tcId, $publicKey, $msg, $sig, $result, $comment, $flags, $ctx
        );
    }

    #[DataProvider('mldsa65VerifyProvider')]
    public function testMldsa65Verify(
        int $tcId,
        string $publicKey,
        string $msg,
        string $sig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
    ): void {
        $this->runVerifyTest(
            VerificationKey65::class,
            Signature65::class,
            $tcId, $publicKey, $msg, $sig, $result, $comment, $flags, $ctx
        );
    }

    #[DataProvider('mldsa87VerifyProvider')]
    public function testMldsa87Verify(
        int $tcId,
        string $publicKey,
        string $msg,
        string $sig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
    ): void {
        $this->runVerifyTest(
            VerificationKey87::class,
            Signature87::class,
            $tcId, $publicKey, $msg, $sig, $result, $comment, $flags, $ctx
        );
    }

    #[DataProvider('mldsa44SignSeedProvider')]
    public function testMldsa44SignSeed(
        int $tcId,
        string $privateSeed,
        string $publicKey,
        string $msg,
        string $expectedSig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
        string $mu,
    ): void {
        $this->runSignSeedTest(
            Params::MLDSA44,
            $tcId, $privateSeed, $publicKey, $msg,
            $expectedSig, $result, $comment, $flags, $ctx, $mu
        );
    }

    #[DataProvider('mldsa65SignSeedProvider')]
    public function testMldsa65SignSeed(
        int $tcId,
        string $privateSeed,
        string $publicKey,
        string $msg,
        string $expectedSig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
        string $mu,
    ): void {
        $this->runSignSeedTest(
            Params::MLDSA65,
            $tcId, $privateSeed, $publicKey, $msg,
            $expectedSig, $result, $comment, $flags, $ctx, $mu
        );
    }

    #[DataProvider('mldsa87SignSeedProvider')]
    public function testMldsa87SignSeed(
        int $tcId,
        string $privateSeed,
        string $publicKey,
        string $msg,
        string $expectedSig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
        string $mu,
    ): void {
        $this->runSignSeedTest(
            Params::MLDSA87,
            $tcId, $privateSeed, $publicKey, $msg,
            $expectedSig, $result, $comment, $flags, $ctx, $mu
        );
    }

    /**
     * @param class-string $vkClass
     * @param class-string $sigClass
     */
    private function runVerifyTest(
        string $vkClass,
        string $sigClass,
        int $tcId,
        string $publicKey,
        string $msg,
        string $sig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
    ): void {
        $pkBin = hex2bin($publicKey);
        $msgBin = hex2bin($msg);
        $sigBin = hex2bin($sig);
        $ctxBin = $ctx !== '' ? hex2bin($ctx) : '';
        self::assertNotFalse($pkBin);
        self::assertNotFalse($msgBin);
        self::assertNotFalse($sigBin);

        // Context > 255 bytes must be rejected
        if ($ctxBin !== false && strlen($ctxBin) > 255) {
            $valid = false;
        } else {
            if ($ctxBin === false) {
                $ctxBin = '';
            }
            try {
                $vk = $vkClass::fromBytes($pkBin);
                $signature = $sigClass::fromBytes($sigBin);
                $valid = $vk->verify($signature, $msgBin, $ctxBin);
            } catch (MLDSAInternalException) {
                // Parse failure = invalid
                $valid = false;
            }
        }

        if ($result === 'valid') {
            $this->assertTrue(
                $valid,
                "Test #{$tcId} ({$comment}) expected valid but got invalid"
            );
        } elseif ($result === 'invalid') {
            $this->assertFalse(
                $valid,
                "Test #{$tcId} ({$comment}) expected invalid but got valid"
            );
        }
    }

    private function runSignSeedTest(
        Params $params,
        int $tcId,
        string $privateSeed,
        string $publicKey,
        string $msg,
        string $expectedSig,
        string $result,
        string $comment,
        array $flags,
        string $ctx,
        string $mu,
    ): void {
        if ($result !== 'valid') {
            $this->markTestSkipped("Non-valid sign test #{$tcId}");
        }
        if (!empty($mu) && empty($msg)) {
            $this->markTestSkipped("We don't support external mu");
        }

        $seedBin = hex2bin($privateSeed);
        $msgBin = hex2bin($msg);
        $ctxBin = hex2bin($ctx);
        self::assertNotFalse($seedBin);
        self::assertNotFalse($msgBin);
        self::assertNotFalse($ctxBin);

        $sk = InternalSigningKey::keyGenInternal($params, $seedBin);

        $this->assertSame(
            $publicKey,
            bin2hex($sk->vk->bytes()),
            "Public key mismatch for sign test #{$tcId}"
        );
        $rnd = str_repeat("\x00", 32);
        $mPrime = Operations::prepareMessage($msgBin, $ctxBin);
        $sig = $sk->signInternal($mPrime, $rnd);

        $this->assertSame(
            $expectedSig,
            bin2hex($sig->bytes()),
            "Signature mismatch for sign test #{$tcId} ({$comment})"
        );
    }

    private static function loadVerifyTests(string $name): array
    {
        $rows = GenericProvider::load($name, ['publicKey']);
        return array_map(function ($row) {
            return [
                $row['tcId'],
                $row['publicKey'],
                $row['msg'],
                $row['sig'],
                $row['result'],
                $row['comment'] ?? '',
                $row['flags'] ?? [],
                $row['ctx'] ?? '',
            ];
        }, $rows);
    }

    private static function loadSignSeedTests(string $name): array
    {
        $rows = GenericProvider::load($name, ['privateSeed', 'publicKey']);
        return array_map(function ($row) {
            return [
                $row['tcId'],
                $row['privateSeed'] ?? '',
                $row['publicKey'] ?? '',
                $row['msg'] ?? '',
                $row['sig'] ?? '',
                $row['result'],
                $row['comment'] ?? '',
                $row['flags'] ?? [],
                $row['ctx'] ?? '',
                $row['mu'] ?? '',
            ];
        }, $rows);
    }
}
