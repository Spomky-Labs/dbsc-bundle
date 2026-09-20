<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * Issues and validates single-use challenges.
 */
interface ChallengeManagerInterface
{
    /**
     * Issues a single-use challenge. `$ttl` overrides the configured lifetime, in seconds, for
     * challenges that must outlive it (e.g. one pre-provisioned for the next refresh).
     */
    public function issue(?string $sessionIdentifier = null, ?string $authorization = null, ?int $ttl = null): Challenge;

    /**
     * Validates and consumes a presented challenge so it cannot be replayed, returning the
     * consumed challenge so the caller can inspect what was bound to it (session, authorization).
     */
    public function consume(string $value, ?string $expectedSessionIdentifier = null): Challenge;
}
