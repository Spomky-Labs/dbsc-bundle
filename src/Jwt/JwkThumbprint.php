<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

use Jose\Component\Core\JWK;

/**
 * JWK thumbprint (RFC 7638) as DBSC uses it to identify a device key across sites: SHA-256,
 * base64url-encoded without padding. It is the `provider_key` a relying party sends in its
 * registration header, and what the embedded key of the resulting proof must hash to.
 */
final class JwkThumbprint
{
    /**
     * @param array<string, mixed> $jwk
     */
    public static function sha256(array $jwk): string
    {
        return (new JWK($jwk))->thumbprint('sha256');
    }
}
