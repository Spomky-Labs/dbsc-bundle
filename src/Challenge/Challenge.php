<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * A single-use challenge tied to a session identifier and an expiry timestamp.
 *
 * On registration the challenge also carries the optional `authorization` value emitted in the
 * `Secure-Session-Registration` header, so the proof can be checked to echo it back exactly as
 * the spec requires.
 */
final readonly class Challenge
{
    public function __construct(
        public string $value,
        public int $expiresAt,
        public ?string $sessionIdentifier = null,
        public ?string $authorization = null,
    ) {
    }

    public function isExpired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
