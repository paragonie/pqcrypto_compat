<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal;

use ParagonIE\PQCrypto\Attributes\Internal;
use ParagonIE\PQCrypto\Util;
use function array_map;
use function hex2bin;
use function min;
use function pack;
use function str_pad;
use function strlen;
use function substr;
use function unpack;

#[Internal]
final class Keccak extends Util
{
    private const ROUNDS = 24;

    private const ROTC = [
        1, 3, 6, 10, 15, 21, 28, 36,
        45, 55, 2, 14, 27, 41, 56, 8,
        25, 43, 62, 18, 39, 61, 20, 44,
    ];

    private const PILN = [
        10, 7, 11, 17, 18, 3, 5, 16,
        8, 21, 24, 4, 15, 23, 19, 13,
        12, 2, 20, 14, 22, 9, 6, 1,
    ];

    /** @var int[] */
    private array $state;

    private string $buffer = '';
    private int $rate;
    private int $suffix;
    private bool $squeezing = false;
    private string $squeezeBuffer = '';
    private static ?array $cachedRC = null;

    /**
     * @return int[]
     */
    private static function roundConstants(): array
    {
        if (self::$cachedRC !== null) {
            return self::$cachedRC;
        }
        self::$cachedRC = array_map(
            static fn(string $hex): int => (
            unpack('J', hex2bin($hex))[1]
            ),
            [
                '0000000000000001', '0000000000008082',
                '800000000000808A', '8000000080008000',
                '000000000000808B', '0000000080000001',
                '8000000080008081', '8000000000008009',
                '000000000000008A', '0000000000000088',
                '0000000080008009', '000000008000000A',
                '000000008000808B', '800000000000008B',
                '8000000000008089', '8000000000008003',
                '8000000000008002', '8000000000000080',
                '000000000000800A', '800000008000000A',
                '8000000080008081', '8000000000008080',
                '0000000080000001', '8000000080008008',
            ]
        );
        return self::$cachedRC;
    }

    private function __construct(int $rate, int $suffix = 0x1F)
    {
        $this->rate = $rate;
        $this->suffix = $suffix;
        $this->state = [
            0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
    }

    /**
     * SHAKE128: rate=168, capacity=256
     */
    public static function shake128(): self
    {
        return new self(168, 0x1F);
    }

    /**
     * SHAKE256: rate=136, capacity=512
     */
    public static function shake256(): self
    {
        return new self(136, 0x1F);
    }

    public function absorb(string $data): self
    {
        $this->buffer .= $data;
        while (strlen($this->buffer) >= $this->rate) {
            $this->absorbBlock(
                substr($this->buffer, 0, $this->rate)
            );
            $this->buffer = substr(
                $this->buffer, $this->rate
            );
        }
        return $this;
    }

    public function squeeze(int $length): string
    {
        if (!$this->squeezing) {
            $this->finalize();
        }

        $output = '';

        if ($this->squeezeBuffer !== '') {
            $take = min($length, strlen($this->squeezeBuffer));
            $output .= substr($this->squeezeBuffer, 0, $take);
            $this->squeezeBuffer = substr($this->squeezeBuffer, $take);
            $length -= $take;
        }

        while ($length > 0) {
            $block = $this->squeezeBlock();
            $take = min($length, $this->rate);
            $output .= substr($block, 0, $take);
            if ($take < $this->rate) {
                $this->squeezeBuffer = substr($block, $take);
            }
            $length -= $take;
        }

        return $output;
    }

    private function finalize(): void
    {
        $padLen = strlen($this->buffer);
        $pad = str_pad($this->buffer, $this->rate, "\0");

        $pad[$padLen] = self::chr(
            self::ord($pad[$padLen]) | $this->suffix
        );
        $last = $this->rate - 1;
        $pad[$last] = self::chr(self::ord($pad[$last]) | 0x80);

        $this->absorbBlock($pad);
        $this->squeezing = true;
        $this->buffer = '';
    }

    private function absorbBlock(string $block): void
    {
        $words = $this->rate >> 3;
        for ($i = 0; $i < $words; $i++) {
            $this->state[$i] ^= unpack('P', $block, $i << 3)[1];
        }
        $this->permute();
    }

    private function squeezeBlock(): string
    {
        $block = '';
        $words = $this->rate >> 3;
        for ($i = 0; $i < $words; $i++) {
            $block .= pack('P', $this->state[$i]);
        }
        $this->permute();
        return $block;
    }

    private function permute(): void
    {
        $st = &$this->state;
        $rc = self::roundConstants();

        for ($round = 0; $round < self::ROUNDS; $round++) {
            $c0 = $st[0] ^ $st[5] ^ $st[10] ^ $st[15] ^ $st[20];
            $c1 = $st[1] ^ $st[6] ^ $st[11] ^ $st[16] ^ $st[21];
            $c2 = $st[2] ^ $st[7] ^ $st[12] ^ $st[17] ^ $st[22];
            $c3 = $st[3] ^ $st[8] ^ $st[13] ^ $st[18] ^ $st[23];
            $c4 = $st[4] ^ $st[9] ^ $st[14] ^ $st[19] ^ $st[24];

            $d0 = $c4 ^ self::rotl64($c1, 1);
            $d1 = $c0 ^ self::rotl64($c2, 1);
            $d2 = $c1 ^ self::rotl64($c3, 1);
            $d3 = $c2 ^ self::rotl64($c4, 1);
            $d4 = $c3 ^ self::rotl64($c0, 1);

            $st[0] ^= $d0;
            $st[1] ^= $d1;
            $st[2] ^= $d2;
            $st[3] ^= $d3;
            $st[4] ^= $d4;
            $st[5] ^= $d0;
            $st[6] ^= $d1;
            $st[7] ^= $d2;
            $st[8] ^= $d3;
            $st[9] ^= $d4;
            $st[10] ^= $d0;
            $st[11] ^= $d1;
            $st[12] ^= $d2;
            $st[13] ^= $d3;
            $st[14] ^= $d4;
            $st[15] ^= $d0;
            $st[16] ^= $d1;
            $st[17] ^= $d2;
            $st[18] ^= $d3;
            $st[19] ^= $d4;
            $st[20] ^= $d0;
            $st[21] ^= $d1;
            $st[22] ^= $d2;
            $st[23] ^= $d3;
            $st[24] ^= $d4;

            $current = $st[1];
            for ($i = 0; $i < 24; $i++) {
                $j = self::PILN[$i];
                $temp = $st[$j];
                $st[$j] = self::rotl64(
                    $current,
                    self::ROTC[$i]
                );
                $current = $temp;
            }

            // χ
            for ($y = 0; $y < 25; $y += 5) {
                $t0 = $st[$y];
                $t1 = $st[$y + 1];
                $t2 = $st[$y + 2];
                $t3 = $st[$y + 3];
                $t4 = $st[$y + 4];
                $st[$y] = $t0 ^ ((~$t1) & $t2);
                $st[$y + 1] = $t1 ^ ((~$t2) & $t3);
                $st[$y + 2] = $t2 ^ ((~$t3) & $t4);
                $st[$y + 3] = $t3 ^ ((~$t4) & $t0);
                $st[$y + 4] = $t4 ^ ((~$t0) & $t1);
            }

            $st[0] ^= $rc[$round];
        }
    }

    private static function rotl64(int $x, int $n): int
    {
        return ($x << $n) | (
                ($x >> (64 - $n))
                    &
                ((1 << $n) - 1)
            );
    }
}
