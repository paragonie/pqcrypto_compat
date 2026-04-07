<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

enum Params
{
    case MLDSA44;
    case MLDSA65;
    case MLDSA87;

    public function tau(): int
    {
        return match ($this) {
            self::MLDSA44 => 39,
            self::MLDSA65 => 49,
            self::MLDSA87 => 60,
        };
    }

    public function lambda(): int
    {
        return match ($this) {
            self::MLDSA44 => 128,
            self::MLDSA65 => 192,
            self::MLDSA87 => 256,
        };
    }

    public function logGamma1(): int
    {
        return match ($this) {
            self::MLDSA44 => 17,
            self::MLDSA65, self::MLDSA87 => 19,
        };
    }

    public function gamma2(): int
    {
        return match ($this) {
            self::MLDSA44 => 95232, // (Field::Q - 1) / 88,
            default => 261888, // (Field::Q - 1) / 32,
        };
    }

    public function k(): int
    {
        return match ($this) {
            self::MLDSA44 => 4,
            self::MLDSA65 => 6,
            self::MLDSA87 => 8,
        };
    }

    public function l(): int
    {
        return match ($this) {
            self::MLDSA44 => 4,
            self::MLDSA65 => 5,
            self::MLDSA87 => 7,
        };
    }

    public function eta(): int
    {
        return match ($this) {
            self::MLDSA44, self::MLDSA87 => 2,
            self::MLDSA65 => 4,
        };
    }

    public function beta(): int
    {
        return match ($this) {
            self::MLDSA44 => 78,
            self::MLDSA65 => 196,
            self::MLDSA87 => 120,
        };
    }

    public function omega(): int
    {
        return match ($this) {
            self::MLDSA44 => 80,
            self::MLDSA65 => 55,
            self::MLDSA87 => 75,
        };
    }

    public function challengeEntropy(): int
    {
        return match ($this) {
            self::MLDSA44 => 192,
            self::MLDSA65 => 225,
            self::MLDSA87 => 257,
        };
    }

    public function publicKeySize(): int
    {
        return match ($this) {
            self::MLDSA44 => 1312,
            self::MLDSA65 => 1952,
            self::MLDSA87 => 2592,
        };
    }

    public function signatureSize(): int
    {
        return match ($this) {
            self::MLDSA44 => 2420,
            self::MLDSA65 => 3309,
            self::MLDSA87 => 4627,
        };
    }

    public function w1bits(): int
    {
        return match ($this) {
            self::MLDSA44 => 6,
            self::MLDSA65 => 4,
            self::MLDSA87 => 4,
        };
    }
}
