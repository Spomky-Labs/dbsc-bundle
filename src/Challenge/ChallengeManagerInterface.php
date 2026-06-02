<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * Issues and validates single-use challenges.
 */
interface ChallengeManagerInterface
{
    public function issue(?string $sessionIdentifier = null): Challenge;

    /**
     * Validates and consumes a presented challenge so it cannot be replayed.
     */
    public function consume(string $value, ?string $expectedSessionIdentifier = null): void;
}
