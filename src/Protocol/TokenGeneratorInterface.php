<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * Generates opaque, URL-safe random identifiers (session identifiers, bound-cookie values).
 */
interface TokenGeneratorInterface
{
    /**
     * @param int<1, max> $bytes
     */
    public function generate(int $bytes = 32): string;
}
