<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLKem;

use ArrayAccess;
use ParagonIE\PQCrypto\Attributes\Internal;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Internal\Object256;

/**
 * @implements ArrayAccess<int, int>
 */
#[Internal]
final class RingElement extends Object256 implements ArrayAccess
{
    public static function zero(): self
    {
        return new self();
    }

    /**
     * @param int[] $coefficients
     *
     * @throws MLKemInternalException
     */
    public static function fromArray(array $coefficients): self
    {
        if (count($coefficients) !== 256) {
            throw new MLKemInternalException("RingElement::fromArray() expects 256 elements");
        }
        return new self(...$coefficients);
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
