<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests\Internal\MLKem;

use ParagonIE\PQCrypto\Internal\MLKem\FieldElement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(FieldElement::class)]
class FieldElementTest extends TestCase
{
    public function testAdd(): void
    {
        for ($i = 0; $i < FieldElement::Q; ++$i) {
            for ($j = 0; $j < 100; ++$j) {
                $x = ($i + $j) % FieldElement::Q;
                $this->assertSame($x, FieldElement::add($i, $j));
            }
        }
    }

    public function testSub(): void
    {
        for ($i = 0; $i < FieldElement::Q; ++$i) {
            for ($j = 0; $j < 100; ++$j) {
                $x = ($i - $j) % FieldElement::Q;
                if ($x < 0) {
                    $x += FieldElement::Q;
                }
                $this->assertSame($x, FieldElement::sub($i, $j));

                $x = ($j - $i) % FieldElement::Q;
                if ($x < 0) {
                    $x += FieldElement::Q;
                }
                $this->assertSame($x, FieldElement::sub($j, $i));
            }
        }
    }
}
