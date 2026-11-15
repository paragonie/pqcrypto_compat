<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\DecapsKeyInterface;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\MLDSA\InternalSigningKey;
use ParagonIE\PQCrypto\Internal\MLDSA\Params;
use ParagonIE\PQCrypto\MLDSA44\SigningKey;
use ParagonIE\PQCrypto\MLDSA44\SigningKey as SK44;
use ParagonIE\PQCrypto\MLDSA65\SigningKey as SK65;
use ParagonIE\PQCrypto\MLDSA87\SigningKey as SK87;
use ParagonIE\PQCrypto\MLKem1024;
use ParagonIE\PQCrypto\MLKem512;
use ParagonIE\PQCrypto\MLKem768;
use ParagonIE\PQCrypto\XWing;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

final class SecurityRegressionTest extends TestCase
{
    public static function invalidSeedProvider(): array
    {
        $cases = [];
        foreach ([44, 65, 87] as $level) {
            foreach ([0, 1, 31, 33, 64, 256] as $length) {
                foreach (['import', 'internal', 'compat'] as $entry) {
                    $cases["$level/$entry/$length"] = [$level, $length, $entry];
                }
            }
        }
        return $cases;
    }

    /**
     * @throws MLDSAInternalException
     */
    #[DataProvider('invalidSeedProvider')]
    public function testMalformedSigningSeedsAreRejected(int $level, int $length, string $entry): void
    {
        $seed = str_repeat('S', $length);
        /** @var class-string<SK44|SK65|SK87> $class */
        $class = 'ParagonIE\\PQCrypto\\MLDSA' . $level . '\\SigningKey';
        $params = constant(Params::class . '::MLDSA' . $level);
        $sign = 'mldsa' . $level . '_sign';
        $this->expectException(MLDSAInternalException::class);
        match ($entry) {
            'import' => $class::fromBytes($seed),
            'internal' => InternalSigningKey::keyGenInternal($params, $seed),
            'compat' => Compat::$sign($seed, 'message'),
        };
    }

    public static function decapsulationProvider(): array
    {
        $cases = [];
        foreach (['mlkem512', 'mlkem768', 'mlkem1024', 'xwing'] as $algorithm) {
            foreach (['compat-string', 'compat-object', 'static', 'object'] as $entry) {
                $cases["$algorithm/$entry"] = [$algorithm, $entry];
            }
        }
        return $cases;
    }

    #[DataProvider('decapsulationProvider')]
    public function testDecapsulationExceptionArgumentsAreRedacted(string $algorithm, string $entry): void
    {
        if (PHP_VERSION_ID < 80200) {
            $this->markTestSkipped('SensitiveParameter requires PHP 8.2');
        }
        $seed = str_repeat('AUDITKEY', $algorithm === 'xwing' ? 4 : 8);
        /** @var class-string<XWing|MLKem512|MLKem768|MLKem1024> $base */
        $base = 'ParagonIE\\PQCrypto\\' . ($algorithm === 'xwing' ? 'XWing' : 'MLKem' . substr($algorithm, 5));
        /** @var class-string<DecapsKeyInterface> $keyClass */
        $keyClass = $base . '\\DecapsulationKey';
        $key = new $keyClass($seed);
        $decaps = $algorithm . '_decaps';
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            try {
                match ($entry) {
                    'compat-string' => Compat::$decaps($seed, 'bad'),
                    'compat-object' => Compat::$decaps($key, 'bad'),
                    'static' => $base::decapsulate($key, 'bad'),
                    'object' => $key->decapsulate('bad'),
                };
                $this->fail('Malformed ciphertext must throw');
            } catch (Throwable $e) {
                $this->assertNotInstanceOf(AssertionFailedError::class, $e);
                $this->assertInstanceOf(\Exception::class, $e);
                foreach ($e->getTrace() as $frame) {
                    // Exclude PHPUnit runner arguments, which contain the whole test suite.
                    if (!str_starts_with($frame['class'] ?? '', 'ParagonIE\\PQCrypto\\')) {
                        continue;
                    }
                    if (strlen($seed) >= 16) {
                        $this->assertFalse(
                            str_contains(
                                var_export($frame['args'] ?? [], true),
                                $seed
                            ),
                            'Secret seed retained in library trace arguments'
                        );
                    }
                    foreach ($frame['args'] ?? [] as $argument) {
                        $this->assertNotSame($seed, $argument);
                        $this->assertNotSame($key, $argument);
                    }
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    /**
     * @throws MLDSAInternalException
     */
    #[DataProvider('invalidSeedProvider')]
    public function testRejectedSigningSeedIsAbsentFromTrace(int $level, int $length, string $entry): void
    {
        if (PHP_VERSION_ID < 80200 || $length === 0) {
            $this->markTestSkipped('Requires redaction support and a nonempty marker');
        }
        $seed = str_repeat('S', $length);
        /** @var class-string<SigningKey> $class */
        $class = 'ParagonIE\\PQCrypto\\MLDSA' . $level . '\\SigningKey';
        $params = constant(Params::class . '::MLDSA' . $level);
        $sign = 'mldsa' . $level . '_sign';
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            try {
                match ($entry) {
                    'import' => $class::fromBytes($seed),
                    'internal' => InternalSigningKey::keyGenInternal($params, $seed),
                    'compat' => Compat::$sign($seed, 'message'),
                };
                $this->fail('Malformed signing seed must throw');
            } catch (MLDSAInternalException $e) {
                foreach ($e->getTrace() as $frame) {
                    // Exclude PHPUnit runner arguments, which contain the whole test suite.
                    if (!str_starts_with($frame['class'] ?? '', 'ParagonIE\\PQCrypto\\')) {
                        continue;
                    }
                    if (strlen($seed) >= 16) {
                        $this->assertFalse(
                            str_contains(
                                var_export($frame['args'] ?? [], true),
                                $seed
                            ),
                            'Secret seed retained in library trace arguments'
                        );
                    }
                    foreach ($frame['args'] ?? [] as $argument) {
                        $this->assertNotSame($seed, $argument);
                    }
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public static function secretKeyProvider(): array
    {
        $cases = [];
        foreach ([512, 768, 1024] as $level) {
            $cases["ML-KEM-$level"] = ['ParagonIE\\PQCrypto\\MLKem' . $level . '\\DecapsulationKey', 64];
        }
        $cases['X-Wing'] = ['ParagonIE\\PQCrypto\\XWing\\DecapsulationKey', 32];
        foreach ([44, 65, 87] as $level) {
            $cases["ML-DSA-$level"] = ['ParagonIE\\PQCrypto\\MLDSA' . $level . '\\SigningKey', 32];
        }
        $cases['Internal ML-DSA'] = [InternalSigningKey::class, 32];
        return $cases;
    }

    /**
     * @param class-string<SigningKey> $class
     * @param int $length
     * @throws MLDSAInternalException
     */
    #[DataProvider('secretKeyProvider')]
    public function testDebugOutputHidesSecretKeys(string $class, int $length): void
    {
        $seed = str_repeat('AUDITKEY', $length >> 3);
        if ($class === InternalSigningKey::class) {
            $key = InternalSigningKey::keyGenInternal(Params::MLDSA44, $seed);
        } elseif (str_ends_with($class, '\\SigningKey')) {
            $key = $class::fromBytes($seed);
        } else {
            $key = new $class($seed);
        }
        ob_start();
        try {
            var_dump($key);
            print_r($key);
        } finally {
            $output = ob_get_clean();
        }
        $this->assertStringNotContainsString($seed, $output);
        if ($key instanceof InternalSigningKey) {
            $this->assertStringNotContainsString($key->K, $output);
        }
        $this->assertSame($seed, $key->bytes(), 'Explicit export must still work');
    }
}
