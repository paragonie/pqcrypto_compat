<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLKem;

use ParagonIE\PQCrypto\Attributes\Internal;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Internal\Keccak;
use ParagonIE\PQCrypto\Util;
use function hash;
use function hash_equals;
use function str_repeat;
use function strlen;
use function substr;

#[Internal]
final class Operations extends Util
{
    /**
     * FIPS 203, Appendix A
     * @var int[]
     */
    public const ZETAS = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848,
        1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
        1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
        650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
        2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100,
        1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
        939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
        1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
        1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    ];

    /**
     * FIPS 203, Appendix A
     * @var int[]
     */
    public const GAMMAS = [
        17, 3312, 2761, 568, 583, 2746, 2649, 680,
        1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
        1409, 1920, 2662, 667, 3281, 48, 233, 3096,
        756, 2573, 2156, 1173, 3015, 314, 3050, 279,
        1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
        1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
        939, 2390, 2308, 1021, 2437, 892, 2388, 941,
        733, 2596, 2337, 992, 268, 3061, 641, 2688,
        1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
        375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
        1063, 2266, 319, 3010, 2773, 556, 757, 2572,
        2099, 1230, 561, 2768, 2466, 863, 2594, 735,
        2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
        1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
        1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
        2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
    ];

    /**
     * @template T of RingElement|NttElement
     * @param T $a
     * @param T $b
     * @return T
     */
    public static function polyAdd(
        RingElement|NttElement $a,
        RingElement|NttElement $b
    ): RingElement|NttElement {
        $r = clone $a;
        for ($i = 0; $i < 256; $i++) {
            $r[$i] = FieldElement::add($a[$i], $b[$i]);
        }
        return $r;
    }

    /**
     * @template T of RingElement|NttElement
     * @param T $a
     * @param T $b
     * @return T
     */
    public static function polySub(
        RingElement|NttElement $a,
        RingElement|NttElement $b
    ): RingElement|NttElement {
        $r = clone $a;
        for ($i = 0; $i < 256; $i++) {
            $r[$i] = FieldElement::sub($a[$i], $b[$i]);
        }
        return $r;
    }

    /**
     * FIPS 203, Algorithm 11
     */
    public static function nttMul(
        NttElement $f,
        NttElement $g
    ): NttElement {
        $h = NttElement::zero();
        for ($i = 0; $i < 256; $i += 2) {
            $a0 = $f[$i];
            $a1 = $f[$i + 1];
            $b0 = $g[$i];
            $b1 = $g[$i + 1];
            $h[$i] = FieldElement::addMul(
                $a0,
                $b0,
                FieldElement::mul($a1, $b1),
                self::GAMMAS[$i >> 1]
            );
            $h[$i + 1] = FieldElement::addMul($a0, $b1, $a1, $b0);
        }
        return $h;
    }

    /**
     * FIPS 203, Algorithm 9
     */
    public static function ntt(RingElement $f): NttElement
    {
        $c = NttElement::zero();
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = $f[$i];
        }
        $k = 1;
        for ($len = 128; $len >= 2; $len >>= 1) {
            for (
                $start = 0;
                $start < 256;
                $start += 2 * $len
            ) {
                $zeta = self::ZETAS[$k++];
                for ($j = 0; $j < $len; $j++) {
                    $p = $start + $j;
                    $q = $start + $len + $j;
                    $a = $c[$p];
                    $b = $c[$q];
                    $t = FieldElement::mul($zeta, $b);
                    $c[$p] = FieldElement::add($a, $t);
                    $c[$q] = FieldElement::sub($a, $t);
                }
            }
        }
        return $c;
    }

    /**
     * FIPS 203, Algorithm 10
     */
    public static function inverseNTT(NttElement $f): RingElement
    {
        $c = RingElement::zero();
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = $f[$i];
        }
        $k = 127;
        for ($len = 2; $len <= 128; $len <<= 1) {
            for (
                $start = 0;
                $start < 256;
                $start += 2 * $len
            ) {
                $zeta = self::ZETAS[$k--];
                for ($j = 0; $j < $len; $j++) {
                    $p = $start + $j;
                    $q = $start + $len + $j;
                    $t = $c[$p];
                    $c[$p] = FieldElement::add(
                        $t, $c[$q]
                    );
                    $c[$q] = FieldElement::mulSub(
                        $zeta, $c[$q], $t
                    );
                }
            }
        }
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = FieldElement::mul($c[$i], 3303);
        }
        return $c;
    }

    /**
     * FIPS 203, Algorithm 7
     */
    public static function sampleNTT(string $rho, int $ii, int $jj): NttElement
    {
        $xof = Keccak::shake128();
        $xof->absorb($rho);
        $xof->absorb(self::chr($ii) . self::chr($jj));

        $a = NttElement::zero();
        $j = 0;
        while ($j < 256) {
            $buf = $xof->squeeze(24);
            for (
                $off = 0;
                $off < 24 && $j < 256;
                $off += 3
            ) {
                $b0 = self::ord($buf[$off]);
                $b1 = self::ord($buf[$off + 1]);
                $b2 = self::ord($buf[$off + 2]);
                $d1 = ($b0 | ($b1 << 8)) & 0xFFF;
                $d2 = (($b1 | ($b2 << 8)) >> 4) & 0xFFF;

                if ($d1 < FieldElement::Q) {
                    $a[$j++] = $d1;
                    if ($j >= 256) {
                        break;
                    }
                }
                if ($d2 < FieldElement::Q) {
                    $a[$j++] = $d2;
                }
            }
        }
        return $a;
    }

    /**
     * FIPS 203, Algorithm 8
     *
     * @throws MLKemInternalException
     */
    public static function samplePolyCBD(
        string $sigma,
        int $counter,
        int $eta
    ): RingElement {
        $prf = Keccak::shake256();
        $prf->absorb($sigma);
        $prf->absorb(self::chr($counter));
        $B = $prf->squeeze(64 * $eta);

        $f = RingElement::zero();

        if ($eta === 2) {
            // 4 bits per coefficient, 2 coefficients per byte.
            for ($i = 0; $i < 256; $i += 2) {
                $b = self::ord($B[$i >> 1]);
                $f[$i] = FieldElement::sub(
                    ($b & 1) + (($b >> 1) & 1),
                    (($b >> 2) & 1) + (($b >> 3) & 1)
                );
                $f[$i + 1] = FieldElement::sub(
                    (($b >> 4) & 1) + (($b >> 5) & 1),
                    (($b >> 6) & 1) + (($b >> 7) & 1)
                );
            }
            return $f;
        } elseif ($eta === 3) {
            // 6 bits per coefficient, 4 coefficients per 3 bytes.
            $byteIdx = 0;
            for ($i = 0; $i < 256; $i += 4) {
                $w = self::ord($B[$byteIdx])
                    | (self::ord($B[$byteIdx + 1]) << 8)
                    | (self::ord($B[$byteIdx + 2]) << 16);
                $byteIdx += 3;
                for ($j = 0; $j < 4; $j++) {
                    $bits = ($w >> (6 * $j)) & 0x3F;
                    $x = ($bits & 1)
                        + (($bits >> 1) & 1)
                        + (($bits >> 2) & 1);
                    $y = (($bits >> 3) & 1)
                        + (($bits >> 4) & 1)
                        + (($bits >> 5) & 1);
                    $f[$i + $j] = FieldElement::sub(
                        $x, $y
                    );
                }
            }
            return $f;
        }
        throw new MLKemInternalException("Unsupported eta: {$eta}");
    }

    /**
     * FIPS 203, Algorithm 5
     */
    public static function polyByteEncode(NttElement $f): string
    {
        $b = '';
        for ($i = 0; $i < 256; $i += 2) {
            $x = $f[$i] | ($f[$i + 1] << 12);
            $b .= self::chr($x & 0xFF)
                . self::chr(($x >> 8) & 0xFF)
                . self::chr(($x >> 16) & 0xFF);
        }
        return $b;
    }

    /**
     * @throws MLKemInternalException
     */
    public static function polyByteDecode(string $b): NttElement
    {
        if (strlen($b) !== 384) {
            throw new MLKemInternalException('Invalid encoding length');
        }
        $f = NttElement::zero();
        for ($i = 0; $i < 256; $i += 2) {
            $j = ($i >> 1) * 3;
            $d = self::ord($b[$j])
                | (self::ord($b[$j + 1]) << 8)
                | (self::ord($b[$j + 2]) << 16);
            $f[$i] = FieldElement::checkReduced($d & 0xFFF);
            $f[$i + 1] = FieldElement::checkReduced($d >> 12);
        }
        return $f;
    }

    public static function ringCompressAndEncode1(RingElement $f): string
    {
        $b = str_repeat("\0", 32);
        for ($i = 0; $i < 256; $i++) {
            $b[$i >> 3] = self::chr(
                (self::ord($b[$i >> 3]) | (FieldElement::compress($f[$i], 1))
                    <<
                ($i & 7))
            );
        }
        return $b;
    }

    public static function ringDecodeAndDecompress1(string $b): RingElement
    {
        $f = RingElement::zero();
        $halfQ = (FieldElement::Q + 1) >> 1;
        for ($i = 0; $i < 256; $i++) {
            $bit = (self::ord($b[$i >> 3]) >> ($i & 7)) & 1;
            $f[$i] = $bit * $halfQ;
        }
        return $f;
    }

    public static function ringCompressAndEncode4(RingElement $f): string
    {
        $b = '';
        for ($i = 0; $i < 256; $i += 2) {
            $b .= self::chr(
                FieldElement::compress($f[$i], 4)
                    |
                (FieldElement::compress($f[$i + 1], 4) << 4)
            );
        }
        return $b;
    }

    public static function ringDecodeAndDecompress4(string $b): RingElement
    {
        $f = RingElement::zero();
        for ($i = 0; $i < 256; $i += 2) {
            $byte = self::ord($b[$i >> 1]);
            $f[$i] = FieldElement::decompress($byte & 0x0F, 4);
            $f[$i + 1] = FieldElement::decompress($byte >> 4, 4);
        }
        return $f;
    }

    public static function ringCompressAndEncode10(RingElement $f): string
    {
        $b = '';
        for ($i = 0; $i < 256; $i += 4) {
            $x = FieldElement::compress($f[$i], 10)
                | (FieldElement::compress($f[$i+1], 10) << 10)
                | (FieldElement::compress($f[$i+2], 10) << 20)
                | (FieldElement::compress($f[$i+3], 10) << 30);
            $b .= self::chr($x & 0xFF)
                . self::chr(($x >> 8) & 0xFF)
                . self::chr(($x >> 16) & 0xFF)
                . self::chr(($x >> 24) & 0xFF)
                . self::chr(($x >> 32) & 0xFF);
        }
        return $b;
    }

    public static function ringDecodeAndDecompress10(string $b): RingElement
    {
        $f = RingElement::zero();
        $j = 0;
        for ($i = 0; $i < 256; $i += 4) {
            $x = self::ord($b[$j])
                | (self::ord($b[$j+1]) << 8)
                | (self::ord($b[$j+2]) << 16)
                | (self::ord($b[$j+3]) << 24)
                | (self::ord($b[$j+4]) << 32);
            $j += 5;
            $f[$i] = FieldElement::decompress($x & 0x3FF, 10);
            $f[$i+1] = FieldElement::decompress(($x >> 10) & 0x3FF, 10);
            $f[$i+2] = FieldElement::decompress(($x >> 20) & 0x3FF, 10);
            $f[$i+3] = FieldElement::decompress(($x >> 30) & 0x3FF, 10);
        }
        return $f;
    }

    private static function ringCompressAndEncodeGeneric(RingElement $f, int $d): string
    {
        $b = '';
        $byte = 0;
        $bIdx = 0;
        for ($i = 0; $i < 256; $i++) {
            $compressed = FieldElement::compress($f[$i], $d);
            $cIdx = 0;
            while ($cIdx < $d) {
                $byte |= (
                        ($compressed >> $cIdx) & 0xFF
                    ) << $bIdx;
                $bits = \min(8 - $bIdx, $d - $cIdx);
                $bIdx += $bits;
                $cIdx += $bits;
                if ($bIdx === 8) {
                    $b .= self::chr($byte & 0xFF);
                    $byte = 0;
                    $bIdx = 0;
                }
            }
        }
        return $b;
    }

    private static function ringDecodeAndDecompressGeneric(string $b, int $d): RingElement
    {
        $f = RingElement::zero();
        $bIdx = 0;
        $byteIdx = 0;
        for ($i = 0; $i < 256; $i++) {
            $c = 0;
            $cIdx = 0;
            while ($cIdx < $d) {
                $c |= (
                    (self::ord($b[$byteIdx]) >> $bIdx) << $cIdx
                );
                $c &= (1 << $d) - 1;
                $bits = \min(8 - $bIdx, $d - $cIdx);
                $bIdx += $bits;
                $cIdx += $bits;
                if ($bIdx === 8) {
                    $byteIdx++;
                    $bIdx = 0;
                }
            }
            $f[$i] = FieldElement::decompress($c, $d);
        }
        return $f;
    }

    public static function ringCompressAndEncode5(RingElement $f): string
    {
        return self::ringCompressAndEncodeGeneric($f, 5);
    }

    public static function ringDecodeAndDecompress5(string $b): RingElement
    {
        return self::ringDecodeAndDecompressGeneric($b, 5);
    }

    public static function ringCompressAndEncode11(RingElement $f): string
    {
        return self::ringCompressAndEncodeGeneric($f, 11);
    }
    public static function ringDecodeAndDecompress11(string $b): RingElement
    {
        return self::ringDecodeAndDecompressGeneric($b, 11);
    }

    /**
     * @throws MLKemInternalException
     */
    public static function ringCompressAndEncode(RingElement $f, int $d): string
    {
        return match ($d) {
            1 => self::ringCompressAndEncode1($f),
            4 => self::ringCompressAndEncode4($f),
            5 => self::ringCompressAndEncode5($f),
            10 => self::ringCompressAndEncode10($f),
            11 => self::ringCompressAndEncode11($f),
            default => throw new MLKemInternalException("Unsupported bit width: {$d}"),
        };
    }

    /**
     * @throws MLKemInternalException
     */
    public static function ringDecodeAndDecompress(string $b, int $d): RingElement
    {
        return match ($d) {
            1 => self::ringDecodeAndDecompress1($b),
            4 => self::ringDecodeAndDecompress4($b),
            5 => self::ringDecodeAndDecompress5($b),
            10 => self::ringDecodeAndDecompress10($b),
            11 => self::ringDecodeAndDecompress11($b),
            default => throw new MLKemInternalException("Unsupported bit width: {$d}"),
        };
    }

    /**
     * @throws MLKemInternalException
     */
    public static function parseEncapsulationKey(int $k, string $ekBytes): array
    {
        $expectedLen = $k * 384 + 32;
        if (strlen($ekBytes) !== $expectedLen) {
            throw new MLKemInternalException(
                'Invalid encapsulation key length'
            );
        }

        $h = hash('sha3-256', $ekBytes, true);

        $t = [];
        $offset = 0;
        for ($i = 0; $i < $k; $i++) {
            $t[$i] = self::polyByteDecode(substr($ekBytes, $offset, 384));
            $offset += 384;
        }

        $rho = substr($ekBytes, $offset, 32);

        $a = [];
        for ($i = 0; $i < $k; $i++) {
            for ($j = 0; $j < $k; $j++) {
                $a[$i * $k + $j] = self::sampleNTT($rho, $j, $i);
            }
        }

        return [
            't' => $t,
            'a' => $a,
            'h' => $h,
            'rho' => $rho,
        ];
    }

    /**
     * @throws MLKemInternalException
     */
    public static function kemKeyGen(
        int $k,
        int $eta1,
        string $d,
        string $z
    ): array {
        $g = hash(
            'sha3-512',
            $d . self::chr($k),
            true
        );
        $rho = substr($g, 0, 32);
        $sigma = substr($g, 32, 32);

        $a = [];
        for ($i = 0; $i < $k; $i++) {
            for ($j = 0; $j < $k; $j++) {
                $a[$i * $k + $j] = self::sampleNTT($rho, $j, $i);
            }
        }

        $N = 0;
        $s = [];
        for ($i = 0; $i < $k; $i++) {
            $s[$i] = self::ntt(self::samplePolyCBD($sigma, $N, $eta1));
            $N++;
        }

        $e = [];
        for ($i = 0; $i < $k; $i++) {
            $e[$i] = self::ntt(self::samplePolyCBD($sigma, $N, $eta1));
            $N++;
        }

        $t = [];
        for ($i = 0; $i < $k; $i++) {
            $t[$i] = $e[$i];
            for ($j = 0; $j < $k; $j++) {
                $t[$i] = self::polyAdd(
                    $t[$i],
                    self::nttMul($a[$i * $k + $j], $s[$j])
                );
            }
        }

        $ek = '';
        for ($i = 0; $i < $k; $i++) {
            $ek .= self::polyByteEncode($t[$i]);
        }
        $ek .= $rho;

        $h = hash('sha3-256', $ek, true);

        return [
            'encapsulationKeyBytes' => $ek,
            'd' => $d,
            'z' => $z,
            'rho' => $rho,
            'h' => $h,
            't' => $t,
            'a' => $a,
            's' => $s,
        ];
    }

    /**
     * @throws MLKemInternalException
     */
    public static function pkeEncrypt(
        int $k,
        int $eta1,
        int $du,
        int $dv,
        array $ek,
        string $m,
        string $rnd
    ): string {
        $N = 0;

        $r = [];
        for ($i = 0; $i < $k; $i++) {
            $r[$i] = self::ntt(
                self::samplePolyCBD($rnd, $N, $eta1)
            );
            $N++;
        }

        $e1 = [];
        for ($i = 0; $i < $k; $i++) {
            $e1[$i] = self::samplePolyCBD($rnd, $N, 2);
            $N++;
        }
        $e2 = self::samplePolyCBD($rnd, $N, 2);

        $u = [];
        for ($i = 0; $i < $k; $i++) {
            $u[$i] = $e1[$i];
            for ($j = 0; $j < $k; $j++) {
                $u[$i] = self::polyAdd(
                    $u[$i],
                    self::inverseNTT(
                        self::nttMul(
                            $ek['a'][$j * $k + $i],
                            $r[$j]
                        )
                    )
                );
            }
        }

        $mu = self::ringDecodeAndDecompress1($m);

        $vNTT = NttElement::zero();
        for ($i = 0; $i < $k; $i++) {
            $vNTT = self::polyAdd(
                $vNTT,
                self::nttMul($ek['t'][$i], $r[$i])
            );
        }
        $v = self::polyAdd(
            self::polyAdd(self::inverseNTT($vNTT), $e2),
            $mu
        );

        // Encode ciphertext.
        $c = '';
        for ($i = 0; $i < $k; $i++) {
            $c .= self::ringCompressAndEncode($u[$i], $du);
        }
        $c .= self::ringCompressAndEncode($v, $dv);

        return $c;
    }

    /**
     * @throws MLKemInternalException
     */
    public static function pkeDecrypt(
        int $k,
        int $du,
        int $dv,
        array $s,
        string $ciphertext
    ): string {
        $encodingDu = 32 * $du;

        $u = [];
        for ($i = 0; $i < $k; $i++) {
            $chunk = substr(
                $ciphertext,
                $encodingDu * $i,
                $encodingDu
            );
            $u[$i] = self::ringDecodeAndDecompress(
                $chunk, $du
            );
        }

        $encodingDv = 32 * $dv;
        $vBytes = substr(
            $ciphertext,
            $encodingDu * $k,
            $encodingDv
        );
        $v = self::ringDecodeAndDecompress($vBytes, $dv);

        $mask = NttElement::zero();
        for ($i = 0; $i < $k; $i++) {
            $mask = self::polyAdd(
                $mask,
                self::nttMul($s[$i], self::ntt($u[$i]))
            );
        }
        $w = self::polySub($v, self::inverseNTT($mask));

        return self::ringCompressAndEncode1($w);
    }

    /**
     * @throws MLKemInternalException
     */
    public static function kemEncaps(
        int $k,
        int $eta1,
        int $du,
        int $dv,
        array $ek,
        string $m
    ): array {
        $g = hash('sha3-512', $m . $ek['h'], true);
        $K = substr($g, 0, 32);
        $r = substr($g, 32, 32);
        $c = self::pkeEncrypt($k, $eta1, $du, $dv, $ek, $m, $r);
        return ['sharedKey' => $K, 'ciphertext' => $c];
    }

    /**
     * @throws MLKemInternalException
     */
    public static function kemDecaps(
        int $k,
        int $eta1,
        int $du,
        int $dv,
        string $z,
        string $h,
        array $encKey,
        array $s,
        string $ciphertext
    ): string {
        $m = self::pkeDecrypt($k, $du, $dv, $s, $ciphertext);

        $g = hash('sha3-512', $m . $h, true);
        $Kprime = substr($g, 0, 32);
        $r = substr($g, 32, 32);

        // Implicit rejection
        $shake = Keccak::shake256();
        $shake->absorb($z);
        $shake->absorb($ciphertext);
        $Kout = $shake->squeeze(32);

        // Re-encrypt.
        $ek = [
            't' => $encKey['t'],
            'a' => $encKey['a'],
        ];
        $c1 = self::pkeEncrypt($k, $eta1, $du, $dv, $ek, $m, $r);

        // Constant-time compare and conditional copy.
        $eq = (int) hash_equals($ciphertext, $c1);
        $mask = -$eq;
        for ($i = 0; $i < 32; $i++) {
            $kp = self::ord($Kprime[$i]);
            $ko = self::ord($Kout[$i]);
            $Kout[$i] = self::chr($ko ^ ($mask & ($kp ^ $ko)));
        }

        return $Kout;
    }
}
