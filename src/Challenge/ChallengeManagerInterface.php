<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * Issues and validates single-use challenges.
 */
interface ChallengeManagerInterface
{
    public function issue(?string $sessionIdentifier = null, ?string $authorization = null): Challenge;

    /**
     * Validates and consumes a presented challenge so it cannot be replayed, returning the
     * consumed challenge so the caller can inspect what was bound to it (session, authorization).
     */
    public function consume(string $value, ?string $expectedSessionIdentifier = null): Challenge;
}
