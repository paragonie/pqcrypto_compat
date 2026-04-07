<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ArrayAccess;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\Object256;

class Ring extends Object256 implements ArrayAccess
{
    public static function zero(): self
    {
        return new Ring();
    }

    public function add(Ring $other): Ring
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::add(
                $cloned->{'c' . $i},
                 $other->{'c' . $i}
            );
        }
        return $cloned;
    }

    public function sub(Ring $other): Ring
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::sub(
                $cloned->{'c' . $i},
                 $other->{'c' . $i}
            );
        }
        return $cloned;
    }

    public function negate(): Ring
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::neg(
                $cloned->{'c' . $i}
            );
        }
        return $cloned;
    }

    public function power2Round(): array
    {
        $r1 = new Ring();
        $r0 = new Ring();
        for ($i = 0; $i < 256; ++$i) {
            [
                $r1->{'c' . $i},
                $r0->{'c' . $i}
            ] = Field::power2round($this->{'c' . $i});
        }
        return [$r1, $r0];
    }

    /**
     * @throws MLDSAInternalException
     */
    public function highBits(Params $params): Ring
    {
        $r1 = new Ring();
        $g2 = $params->gamma2();
        for ($i = 0; $i < 256; ++$i) {
            [$hi, ] = Field::decompose($this->{'c' . $i}, $g2);
            $r1->{'c' . $i} = $hi;
        }
        return $r1;
    }

    /**
     * @throws MLDSAInternalException
     */
    public function lowBits(Params $params): Ring
    {
        $r1 = new Ring();
        $g2 = $params->gamma2();
        for ($i = 0; $i < 256; ++$i) {
            [, $lo] = Field::decompose($this->{'c' . $i}, $g2);
            $r1->{'c' . $i} = $lo;
        }
        return $r1;
    }

    public function infinityNorm(): int
    {
        $norm = 0;
        for ($i = 0; $i < 256; ++$i) {
            $norm = max($norm, Field::infinityNorm($this->{'c' . $i}));
        }
        return $norm;
    }

    public function symmetric(): Ring
    {
        $out = new Ring();
        for ($i = 0; $i < 256; ++$i) {
            $out->{'c' . $i} = Field::symmetric($this->{'c' . $i});
        }
        return $out;
    }

    public function scalarMul(int $c): Ring
    {
        $out = new Ring();
        for ($i = 0; $i < 256; ++$i) {
            $out[$i] = Field::mul($this->{'c' . $i}, $c);
        }
        return $out;
    }

    public static function fromSymmetric(Ring $symmetric): Ring
    {
        $out = new Ring();
        for ($i = 0; $i < 256; ++$i) {
            $out->{'c' . $i} = Field::newFromSymmetric($symmetric->{'c' . $i});
        }
        return $out;
    }

    public function offsetExists(mixed $offset): bool
    {
        return $offset >= 0 && $offset < 256;
    }

    public function offsetGet(mixed $offset): int
    {
        return $this->{'c' . $offset};
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->{'c' . $offset} = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->{'c' . $offset} = 0;
    }
}
