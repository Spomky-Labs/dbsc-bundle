<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final class FixedClock implements ClockInterface
{
    public function __construct(
        private DateTimeImmutable $now,
    ) {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function set(DateTimeImmutable $now): void
    {
        $this->now = $now;
    }
}
