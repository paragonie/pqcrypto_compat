<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ArrayAccess;
use ParagonIE\PQCrypto\Internal\Object256;

class Ntt extends Object256 implements ArrayAccess
{
    public static function zero(): self
    {
        return new Ntt();
    }

    /**
     * FIPS 204, Algorithm 44
     */
    public function add(Ntt $other): Ntt
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::add($cloned->{'c' . $i}, $other->{'c' . $i});
        }
        return $cloned;
    }

    public function sub(Ntt $other): Ntt
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::sub($cloned->{'c' . $i}, $other->{'c' . $i});
        }
        return $cloned;
    }

    /**
     * FIPS 204, Algorithm 45
     */
    public function mul(Ntt $other): Ntt
    {
        $cloned = clone $this;
        for ($i = 0; $i < 256; ++$i) {
            $cloned->{'c' . $i} = Field::mul($cloned->{'c' . $i}, $other->{'c' . $i});
        }
        return $cloned;
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
