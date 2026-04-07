<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLKem;

use ArrayAccess;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Internal\Object256;
use ReturnTypeWillChange;

final class NttElement extends Object256 implements ArrayAccess
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
            throw new MLKemInternalException("NttElement::fromArray() expects 256 elements");
        }
        $e = new self();
        for ($i = 0; $i < 256; $i++) {
            $e->{'c' . $i} = $coefficients[$i];
        }
        return $e;
    }

    #[ReturnTypeWillChange]
    public function offsetExists(mixed $offset): bool
    {
        return $offset >= 0 && $offset < 256;
    }

    #[ReturnTypeWillChange]
    public function offsetGet(mixed $offset): int
    {
        return $this->{'c' . $offset};
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->{'c' . $offset} = $value;
    }

    #[ReturnTypeWillChange]
    public function offsetUnset(mixed $offset): void
    {
        $this->{'c' . $offset} = 0;
    }
}
