<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests\Internal\MLDSA;

use ParagonIE\PQCrypto\Internal\MLDSA\Field;
use ParagonIE\PQCrypto\Internal\MLDSA\Ntt;
use ParagonIE\PQCrypto\Internal\MLDSA\Operations;
use ParagonIE\PQCrypto\Internal\MLDSA\Ring;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Field::class)]
#[CoversClass(Ntt::class)]
#[CoversClass(Ring::class)]
#[CoversClass(Operations::class)]
class FieldTest extends TestCase
{
    public function testAdd(): void
    {
        for ($i = 1; $i < Field::Q; $i <<= 1) {
            for ($j = 0; $j < 1025; ++$j) {
                $this->assertSame(
                    ($j + $i) % Field::Q,
                    Field::add($i, $j)
                );
            }
        }
    }

    public function testSub(): void
    {
        for ($i = 1; $i < Field::Q; $i <<= 1) {
            for ($j = 0; $j < 1025; ++$j) {
                $x = ($i - $j) % Field::Q;
                if ($x < 0) {
                    $x += Field::Q;
                }
                $this->assertSame($x, Field::sub($i, $j));

                $x = ($j - $i) % Field::Q;
                if ($x < 0) {
                    $x += Field::Q;
                }
                $this->assertSame($x, Field::sub($j, $i));
            }
        }
    }

    public function testNeg(): void
    {
        $this->assertSame(0, Field::neg(0));
        $this->assertSame(Field::Q - 1, Field::neg(1));
        $this->assertSame(1, Field::neg(Field::Q - 1));

        for ($i = 1; $i < Field::Q; $i <<= 1) {
            $neg = Field::neg($i);
            $this->assertSame(0, Field::add($i, $neg));
        }
    }

    public function testMul(): void
    {
        $this->assertSame(0, Field::mul(0, 0));
        $this->assertSame(0, Field::mul(0, 1));
        $this->assertSame(0, Field::mul(1, 0));
        $this->assertSame(1, Field::mul(1, 1));

        // a * 1 = a
        for ($i = 1; $i < Field::Q; $i <<= 1) {
            $this->assertSame($i, Field::mul($i, 1));
            $this->assertSame($i, Field::mul(1, $i));
        }

        // Small products that don't need reduction
        $this->assertSame(6, Field::mul(2, 3));
        $this->assertSame(100, Field::mul(10, 10));

        // Products that require reduction
        // (Q-1) * (Q-1) = 1 mod Q
        $this->assertSame(1, Field::mul(Field::Q - 1, Field::Q - 1));

        // (Q-1) * 2 = Q - 2 mod Q
        $this->assertSame(Field::Q - 2, Field::mul(Field::Q - 1, 2));

        // Powers of two
        for ($i = 1; $i < 23; ++$i) {
            $a = 1 << $i;
            $expected = ($a * $a) % Field::Q;
            $this->assertSame(
                $expected,
                Field::mul($a, $a),
                "Failed: ($a * $a) mod Q"
            );
        }
    }

    public function testMulAssociative(): void
    {
        $vals = [0, 1, 2, 3, 1000, 4190208, Field::Q - 1];
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                foreach ($vals as $c) {
                    $this->assertSame(
                        Field::mul(Field::mul($a, $b), $c),
                        Field::mul($a, Field::mul($b, $c)),
                        "Associativity failed: ($a * $b) * $c"
                    );
                }
            }
        }
    }

    public function testMulCommutative(): void
    {
        $vals = [0, 1, 2, 1000, 4190208, Field::Q - 1];
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                $this->assertSame(
                    Field::mul($a, $b),
                    Field::mul($b, $a),
                    "Commutativity failed: $a * $b"
                );
            }
        }
    }

    public function testNewFromSymmetric(): void
    {
        // Non-negative values stay unchanged
        $this->assertSame(0, Field::newFromSymmetric(0));
        $this->assertSame(1, Field::newFromSymmetric(1));
        $this->assertSame(100, Field::newFromSymmetric(100));

        // Negative values get Q added
        $this->assertSame(Field::Q - 1, Field::newFromSymmetric(-1));
        $this->assertSame(Field::Q - 2, Field::newFromSymmetric(-2));
        $this->assertSame(Field::Q - 100, Field::newFromSymmetric(-100));

        // Round-trip: symmetric -> standard -> symmetric
        $halfQ = (Field::Q - 1) >> 1;
        for ($x = -$halfQ; $x <= $halfQ; $x += 100000) {
            $std = Field::newFromSymmetric($x);
            $this->assertGreaterThanOrEqual(0, $std);
            $this->assertLessThan(Field::Q, $std);

            $back = Field::symmetric($std);
            $this->assertSame($x, $back, "Round-trip failed for $x");
        }
    }

    public function testSymmetric(): void
    {
        $this->assertSame(0, Field::symmetric(0));
        $this->assertSame(1, Field::symmetric(1));
        $this->assertSame(-1, Field::symmetric(Field::Q - 1));
        $this->assertSame(-2, Field::symmetric(Field::Q - 2));

        // Boundary: (Q-1)/2 should remain positive
        $halfQ = (Field::Q - 1) >> 1;
        $this->assertSame($halfQ, Field::symmetric($halfQ));
        // (Q+1)/2 should go negative
        $this->assertSame(-$halfQ, Field::symmetric($halfQ + 1));
    }

    public function testReduceOnce(): void
    {
        // Values in [0, Q) unchanged
        $this->assertSame(0, Field::reduceOnce(0));
        $this->assertSame(1, Field::reduceOnce(1));
        $this->assertSame(Field::Q - 1, Field::reduceOnce(Field::Q - 1));

        // Values in [Q, 2Q) reduced
        $this->assertSame(0, Field::reduceOnce(Field::Q));
        $this->assertSame(1, Field::reduceOnce(Field::Q + 1));
    }

    public function testPower2round(): void
    {
        // Algorithm 35: r0 = a mod 2^D (centered), r1 = (a - r0) / 2^D
        $d = Field::D; // 13
        $twoD = 1 << $d;
        $halfD = 1 << ($d - 1);

        for ($a = 0; $a < 100; ++$a) {
            [$r1, $r0] = Field::power2round($a);
            $this->assertSame($a, $r1 * $twoD + $r0);
            $this->assertGreaterThanOrEqual(-$halfD + 1, $r0);
            $this->assertLessThanOrEqual($halfD, $r0);
        }

        // Spot-check at boundary
        [$r1, $r0] = Field::power2round(Field::Q - 1);
        $this->assertSame(Field::Q - 1, $r1 * $twoD + $r0);
    }

    public function testDecompose(): void
    {
        $gamma2Vals = [95232, 261888];
        foreach ($gamma2Vals as $gamma2) {
            $twoG2 = $gamma2 << 1;
            for ($trial = 0; $trial < 200; ++$trial) {
                // Test a spread of values across [0, Q)
                $a = ($trial * 41983) % Field::Q;
                [$r1, $r0] = Field::decompose($a, $gamma2);

                // r0 must be in (-gamma2, gamma2]
                $this->assertGreaterThan(-$gamma2, $r0, "r0 too small for a=$a, gamma2=$gamma2");
                $this->assertLessThanOrEqual($gamma2, $r0, "r0 too large for a=$a, gamma2=$gamma2");

                // Reconstruction: a = r1 * 2*gamma2 + r0 (mod Q)
                $reconstructed = (($r1 * $twoG2) + $r0) % Field::Q;
                if ($reconstructed < 0) {
                    $reconstructed += Field::Q;
                }
                $this->assertSame($a, $reconstructed, "Decompose reconstruction failed for a=$a, gamma2=$gamma2");
            }
        }
    }

    public function testHighBitsLowBits(): void
    {
        $gamma2 = 95232;
        for ($trial = 0; $trial < 100; ++$trial) {
            $a = ($trial * 83969) % Field::Q;
            [$r1, $r0] = Field::decompose($a, $gamma2);
            $this->assertSame($r1, Field::highBits($a, $gamma2));
            $this->assertSame($r0, Field::lowBits($a, $gamma2));
        }
    }

    public function testMakeHint(): void
    {
        $gamma2 = 95232;
        // When z=0, hint should always be 0
        for ($trial = 0; $trial < 50; ++$trial) {
            $r = ($trial * 167939) % Field::Q;
            $this->assertSame(0, Field::makeHint(0, $r, $gamma2));
        }
    }

    public function testInfinityNorm(): void
    {
        $this->assertSame(0, Field::infinityNorm(0));
        $this->assertSame(1, Field::infinityNorm(1));
        $this->assertSame(1, Field::infinityNorm(Field::Q - 1));
        $this->assertSame(100, Field::infinityNorm(100));
        $this->assertSame(100, Field::infinityNorm(Field::Q - 100));
    }

    public function testNttRoundTrip(): void
    {
        // Create a ring with known coefficients
        $w = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            $w[$i] = ($i * 32771) % Field::Q;
        }

        $ntt = Operations::ntt($w);
        $recovered = Operations::inverseNtt($ntt);

        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(
                $w[$i],
                $recovered[$i],
                "NTT round-trip failed at index $i"
            );
        }
    }

    public function testNttRoundTripZero(): void
    {
        $w = Ring::zero();
        $ntt = Operations::ntt($w);
        $recovered = Operations::inverseNtt($ntt);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(0, $recovered[$i]);
        }
    }

    public function testNttMulIsPolynomialMul(): void
    {
        // NTT(a) * NTT(b) in NTT domain should equal NTT(a * b)
        // Use a simple case: multiply by the identity (all 1s in NTT)
        $a = Ring::zero();
        $a[0] = 1; // x^0 = 1
        $aHat = Operations::ntt($a);

        $b = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            $b[$i] = ($i * 7 + 3) % Field::Q;
        }
        $bHat = Operations::ntt($b);

        // a=1, so a*b = b in polynomial ring
        $cHat = $aHat->mul($bHat);
        $c = Operations::inverseNtt($cHat);

        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(
                $b[$i],
                $c[$i],
                "Polynomial mul by 1 failed at index $i"
            );
        }
    }

    public function testSimpleBitPackUnpackRoundTrip(): void
    {
        // 10-bit values (used in pkEncode for t1)
        $w = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            $w[$i] = $i % 1024; // 10-bit range
        }
        $packed = Operations::simpleBitPack($w, 10);
        $unpacked = Operations::simpleBitUnpack($packed, 10);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(
                $w[$i],
                $unpacked[$i],
                "SimpleBitPack round-trip failed at index $i"
            );
        }
    }

    public function testSimpleBitPackUnpack6Bit(): void
    {
        // 6-bit values (w1bits for ML-DSA-44)
        $w = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            $w[$i] = $i % 44; // valid w1 range for ML-DSA-44
        }
        $packed = Operations::simpleBitPack($w, 6);
        $this->assertCount(192, $packed); // 256 * 6 / 8
        $unpacked = Operations::simpleBitUnpack($packed, 6);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame($w[$i], $unpacked[$i]);
        }
    }

    public function testSimpleBitPackUnpack4Bit(): void
    {
        // 4-bit values (w1bits for ML-DSA-65/87)
        $w = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            $w[$i] = $i % 16;
        }
        $packed = Operations::simpleBitPack($w, 4);
        $this->assertCount(128, $packed); // 256 * 4 / 8
        $unpacked = Operations::simpleBitUnpack($packed, 4);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame($w[$i], $unpacked[$i]);
        }
    }

    public function testBitPackUnpackRoundTrip(): void
    {
        // 17-bit gamma1 (ML-DSA-44): values in [-2^17+1, 2^17]
        $k = 17;
        $gamma1 = 1 << $k;
        $w = Ring::zero();
        for ($i = 0; $i < 256; ++$i) {
            // Symmetric values in [-gamma1+1, gamma1]
            $val = (($i * 997) % ($gamma1 * 2)) - $gamma1 + 1;
            $w[$i] = $val;
        }

        $packed = Operations::bitPack($w, $k);
        $unpacked = Operations::bitUnpack($packed, $k);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(
                $w[$i],
                $unpacked[$i],
                "BitPack round-trip failed at index $i (val={$w[$i]})"
            );
        }
    }

    public function testFromHalfByteEta2(): void
    {
        // eta=2: b < 15, result = eta - (b % 5) mod Q
        for ($b = 0; $b < 15; ++$b) {
            $result = Operations::fromHalfByte(2, $b);
            $this->assertNotNull($result);
            $expected = 2 - ($b % 5);
            if ($expected < 0) {
                $expected += Field::Q;
            }
            $this->assertSame($expected, $result, "fromHalfByte(2, $b)");
        }
        // b = 15 should return null
        $this->assertNull(Operations::fromHalfByte(2, 15));
    }

    public function testFromHalfByteEta4(): void
    {
        // eta=4: b < 9, result = eta - b mod Q
        for ($b = 0; $b < 9; ++$b) {
            $result = Operations::fromHalfByte(4, $b);
            $this->assertNotNull($result);
            $expected = 4 - $b;
            if ($expected < 0) {
                $expected += Field::Q;
            }
            $this->assertSame($expected, $result, "fromHalfByte(4, $b)");
        }
        // b = 9 should return null
        $this->assertNull(Operations::fromHalfByte(4, 9));
    }

    public function testDiv(): void
    {
        $denominators = [95232, 261888, 190464, 523776];
        foreach ($denominators as $d) {
            for ($n = 0; $n < $d * 3; $n += $d + 1) {
                [$quo, $rem] = Field::div($n, $d);
                $this->assertSame($n, $quo * $d + $rem, "div($n, $d)");
                $this->assertGreaterThanOrEqual(0, $rem);
                $this->assertLessThan($d, $rem);
            }
        }
    }
}
