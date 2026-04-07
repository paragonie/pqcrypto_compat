<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Tests;

use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\MLKem1024;
use ParagonIE\PQCrypto\MLKem1024\{
    DecapsulationKey,
    EncapsulationKey,
};
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

#[CoversClass(MLKem1024::class)]
class MLKem1024Test extends TestCase
{
    /**
     * @return void
     * @throws MLKemInternalException
     * @throws RandomException
     */
    public function testMLKem1024(): void
    {
        [$decKey, $encKey] = MLKem1024::generateKeypair();
        $this->assertInstanceOf(EncapsulationKey::class, $encKey);
        $this->assertInstanceOf(DecapsulationKey::class, $decKey);

        ['sharedKey' => $ss1, 'ciphertext' => $ct1] = $encKey->encapsulate();
        ['sharedKey' => $ss2, 'ciphertext' => $ct2] = MLKem1024::encapsulate($encKey);
        $this->assertIsString($ss1);
        $this->assertIsString($ss2);
        $this->assertIsString($ct1);
        $this->assertIsString($ct2);
        $this->assertSame(32, strlen($ss1));
        $this->assertSame(32, strlen($ss2));
        $this->assertSame(MLKem1024::CIPHERTEXT_SIZE, strlen($ct1));
        $this->assertSame(MLKem1024::CIPHERTEXT_SIZE, strlen($ct2));

        $ss1prime = MLKem1024::decapsulate($decKey, $ct1);
        $ss2prime = $decKey->decapsulate($ct2);
        $this->assertSame($ss1, $ss1prime);
        $this->assertSame($ss2, $ss2prime);
    }
}
