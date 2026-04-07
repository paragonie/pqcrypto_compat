<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\{
    Exception\MLKemInternalException,
    MLKem512,
    MLKem768,
    MLKem1024};
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use TrailOfBits\Wycheproof\Provider\GenericProvider;

#[Group("ML-KEM")]
#[Group("Wycheproof")]
#[CoversClass(MLKem512::class)]
final class MLKemWycheproofTest extends TestCase
{
    public static function keygenSeed512Provider(): array
    {
        return self::loadKeygen('mlkem_512_keygen_seed');
    }

    public static function keygenSeed768Provider(): array
    {
        return self::loadKeygen('mlkem_768_keygen_seed');
    }

    public static function keygenSeed1024Provider(): array
    {
        return self::loadKeygen('mlkem_1024_keygen_seed');
    }

    /**
     * @dataProvider keygenSeed512Provider
     * @throws MLKemInternalException
     */
    #[DataProvider('keygenSeed512Provider')]
    public function testKeyGen512(
        int $tcId,
        string $seed,
        string $expectedEk,
        string $result
    ): void {
        $this->runKeyGenTest(MLKem512::class, $tcId, $seed, $expectedEk, $result);
    }

    /**
     * @dataProvider keygenSeed768Provider
     * @throws MLKemInternalException
     */
    #[DataProvider('keygenSeed768Provider')]
    public function testKeyGen768(
        int $tcId,
        string $seed,
        string $expectedEk,
        string $result
    ): void {
        $this->runKeyGenTest(MLKem768::class, $tcId, $seed, $expectedEk, $result);
    }

    /**
     * @dataProvider keygenSeed1024Provider
     * @throws MLKemInternalException
     */
    #[DataProvider('keygenSeed1024Provider')]
    public function testKeyGen1024(
        int $tcId,
        string $seed,
        string $expectedEk,
        string $result
    ): void {
        $this->runKeyGenTest(MLKem1024::class, $tcId, $seed, $expectedEk, $result);
    }

    /**
     * @param class-string<MLKem512|MLKem768|MLKem1024> $class
     * @param int $tcId
     * @param string $seed
     * @param string $expectedEk
     * @param string $result
     * @throws MLKemInternalException
     */
    private function runKeyGenTest(
        string $class,
        int $tcId,
        string $seed,
        string $expectedEk,
        string $result
    ): void {
        $seedBin = hex2bin($seed);
        self::assertNotFalse($seedBin);
        $d = substr($seedBin, 0, 32);
        $z = substr($seedBin, 32, 32);

        if ($result !== 'valid') {
            $this->markTestSkipped(
                "Non-valid keygen test #{$tcId}"
            );
        }

        $keys = $class::keyGenInternal($d, $z);
        $this->assertSame(
            $expectedEk,
            bin2hex($keys['encapsulationKey']),
            "KeyGen mismatch for test #{$tcId}"
        );
    }

    public static function encaps512Provider(): array
    {
        return self::loadEncaps('mlkem_512_encaps');
    }

    public static function encaps768Provider(): array
    {
        return self::loadEncaps('mlkem_768_encaps');
    }

    public static function encaps1024Provider(): array
    {
        return self::loadEncaps('mlkem_1024_encaps');
    }

    /**
     * @throws MLKemInternalException
     */
    #[DataProvider('encaps512Provider')]
    public function testEncaps512(
        int $tcId,
        string $ek,
        string $m,
        string $expectedC,
        string $expectedK,
        string $result,
        array $flags
    ): void {
        $this->runEncapsTest(
            MLKem512::class, $tcId,
            $ek, $m, $expectedC, $expectedK,
            $result, $flags
        );
    }

    #[DataProvider('encaps768Provider')]
    public function testEncaps768(
        int $tcId,
        string $ek,
        string $m,
        string $expectedC,
        string $expectedK,
        string $result,
        array $flags
    ): void {
        $this->runEncapsTest(
            MLKem768::class, $tcId,
            $ek, $m, $expectedC, $expectedK,
            $result, $flags
        );
    }

    #[DataProvider('encaps1024Provider')]
    public function testEncaps1024(
        int $tcId,
        string $ek,
        string $m,
        string $expectedC,
        string $expectedK,
        string $result,
        array $flags
    ): void {
        $this->runEncapsTest(
            MLKem1024::class, $tcId,
            $ek, $m, $expectedC, $expectedK,
            $result, $flags
        );
    }

    /**
     * @param class-string<MLKem512|MLKem768|MLKem1024> $class
     * @param int $tcId
     * @param string $ek
     * @param string $m
     * @param string $expectedC
     * @param string $expectedK
     * @param string $result
     * @param array $flags
     * @return void
     *
     * @throws MLKemInternalException
     */
    private function runEncapsTest(
        string $class,
        int $tcId,
        string $ek,
        string $m,
        string $expectedC,
        string $expectedK,
        string $result,
        array $flags
    ): void {
        $ekBin = hex2bin($ek);
        $mBin = hex2bin($m);
        self::assertNotFalse($ekBin);
        self::assertNotFalse($mBin);

        if ($result === 'invalid') {
            // Invalid EK should cause rejection during parse.
            if (in_array('ModulusOverflow', $flags, true)) {
                $this->expectException(PQCryptoCompatException::class);
                $class::encapsulateInternal($ekBin, $mBin);
                return;
            }
            $this->markTestSkipped("Unsupported invalid encaps test #{$tcId}");
        }

        $enc = $class::encapsulateInternal($ekBin, $mBin);

        $this->assertSame(
            $expectedK,
            bin2hex($enc['sharedKey']),
            "Shared key mismatch for test #{$tcId}"
        );
        $this->assertSame(
            $expectedC,
            bin2hex($enc['ciphertext']),
            "Ciphertext mismatch for test #{$tcId}"
        );
    }

    private static function loadKeygen(string $name): array
    {
        $rows = GenericProvider::load($name);
        $out = [];
        foreach ($rows as $label => $row) {
            $out[$label] = [
                $row['tcId'],
                $row['seed'],
                $row['ek'],
                $row['result'],
            ];
        }
        return $out;
    }

    private static function loadEncaps(string $name): array
    {
        $rows = GenericProvider::load($name);
        return array_map(function ($row) {
            return [
                $row['tcId'],
                $row['ek'],
                $row['m'],
                $row['c'] ?? '',
                $row['K'] ?? '',
                $row['result'],
                $row['flags'] ?? [],
            ];
        }, $rows);
    }
}
