<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto;

class Util
{
    public static function ord(string $character): int
    {
        return unpack('C', $character)[1];
    }

    public static function chr(int $codepoint): string
    {
        return pack('C', $codepoint);
    }

    public static function byteArrayToString(array $bytes): string
    {
        return pack('C*', ...$bytes);
    }

    public static function stringToByteArray(string $string): array
    {
        $u = unpack('C*', $string);
        return array_values($u);
    }
}
