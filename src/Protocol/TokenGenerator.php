<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * Generates opaque, URL-safe random identifiers for session identifiers and bound-cookie
 * values.
 */
final class TokenGenerator implements TokenGeneratorInterface
{
    /**
     * @param int<1, max> $bytes
     */
    public function generate(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
