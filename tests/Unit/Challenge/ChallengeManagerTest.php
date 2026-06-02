<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Challenge;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Exception\InvalidChallengeException;
use SpomkyLabs\DbscBundle\Tests\FixedClock;

/**
 * @internal
 */
final class ChallengeManagerTest extends TestCase
{
    #[Test]
    public function itIssuesAndConsumesAChallengeOnce(): void
    {
        // Given
        $manager = $this->createManager();
        $challenge = $manager->issue();

        // When
        $manager->consume($challenge->value);

        // Then a second consumption fails (single use)
        $this->expectException(InvalidChallengeException::class);
        $manager->consume($challenge->value);
    }

    #[Test]
    public function itRejectsAnEmptyChallenge(): void
    {
        // Given
        $manager = $this->createManager();

        // Then
        $this->expectException(InvalidChallengeException::class);

        // When
        $manager->consume('');
    }

    #[Test]
    public function itRejectsAnUnknownChallenge(): void
    {
        // Given
        $manager = $this->createManager();

        // Then
        $this->expectException(InvalidChallengeException::class);

        // When
        $manager->consume('never-issued');
    }

    #[Test]
    public function itRejectsAnExpiredChallenge(): void
    {
        // Given
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $manager = new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300);
        $challenge = $manager->issue();

        // When the clock moves past the TTL
        $clock->set(new DateTimeImmutable('2026-01-01T00:10:00+00:00'));

        // Then
        $this->expectException(InvalidChallengeException::class);
        $manager->consume($challenge->value);
    }

    #[Test]
    public function itRejectsAChallengeBoundToAnotherSession(): void
    {
        // Given
        $manager = $this->createManager();
        $challenge = $manager->issue('session-A');

        // Then
        $this->expectException(InvalidChallengeException::class);

        // When consumed for a different session
        $manager->consume($challenge->value, 'session-B');
    }

    #[Test]
    public function itAcceptsAChallengeForItsBoundSession(): void
    {
        // Given
        $manager = $this->createManager();
        $challenge = $manager->issue('session-A');

        // When / Then (no exception)
        $manager->consume($challenge->value, 'session-A');
        static::assertNotSame('', $challenge->value);
    }

    private function createManager(): ChallengeManager
    {
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));

        return new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300);
    }
}
