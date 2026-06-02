<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * Stores issued challenges so a presented proof can be matched against a previously
 * emitted, non-expired, single-use challenge.
 */
interface ChallengeStore
{
    public function save(Challenge $challenge): void;

    /**
     * Returns the stored challenge for the given value, or null if unknown/expired.
     */
    public function get(string $value): ?Challenge;

    /**
     * Atomically consumes (removes) a challenge so it cannot be replayed.
     */
    public function consume(string $value): void;
}
