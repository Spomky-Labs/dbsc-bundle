<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

use Psr\Clock\ClockInterface;

/**
 * Volatile challenge store. Suitable for single-process dev/test only; use a shared
 * implementation (cache, database) in production multi-node deployments.
 */
final class InMemoryChallengeStore implements ChallengeStore
{
    /**
     * @var array<string, Challenge>
     */
    private array $challenges = [];

    public function __construct(
        private readonly ClockInterface $clock,
    ) {
    }

    public function save(Challenge $challenge): void
    {
        $this->challenges[$challenge->value] = $challenge;
    }

    public function get(string $value): ?Challenge
    {
        $challenge = $this->challenges[$value] ?? null;
        if ($challenge === null) {
            return null;
        }

        if ($challenge->isExpired($this->clock->now()->getTimestamp())) {
            unset($this->challenges[$value]);

            return null;
        }

        return $challenge;
    }

    public function consume(string $value): void
    {
        unset($this->challenges[$value]);
    }
}
