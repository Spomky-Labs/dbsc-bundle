<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * A single-use challenge tied to a session identifier and an expiry timestamp.
 */
final readonly class Challenge
{
    public function __construct(
        public string $value,
        public int $expiresAt,
        public ?string $sessionIdentifier = null,
    ) {
    }

    public function isExpired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
