<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Traits;

trait SensitiveDebugInfoTrait
{
    /**
     * Hide secret material from var_dump() and print_r()
     */
    public function __debugInfo(): array
    {
        return [];
    }
}
