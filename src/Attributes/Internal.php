<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Attributes;

use Attribute;

/**
 * Any code segments with this attribute SHOULD NOT be used outside of this library.
 *
 * We make ABSOLUTELY NO GUARANTEES about the stability of internal implementation details.
 * If you use them, you do so at the risk of incompatibility and breakage even across patch releases.
 */
#[Attribute(Attribute::TARGET_ALL)]
class Internal
{}
