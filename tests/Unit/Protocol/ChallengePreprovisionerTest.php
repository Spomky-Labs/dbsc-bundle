<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Protocol;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\ChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Protocol\NullChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Tests\FixedClock;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class ChallengePreprovisionerTest extends TestCase
{
    #[Test]
    public function itAttachesAChallengeBoundToTheSession(): void
    {
        // Given a preprovisioner for a 600 s cookie with a 300 s grace
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $store = new InMemoryChallengeStore($clock);
        $manager = new ChallengeManager($store, $clock, 300);
        $response = new Response();

        // When a successful response is handed to it
        (new ChallengePreprovisioner($manager, 600, 300))->preprovision($response, 'session-1');

        // Then the response carries the challenge with the session id, and the challenge is consumable for that session
        $header = (string) $response->headers->get(SecureSessionHeaders::CHALLENGE);
        static::assertMatchesRegularExpression('/^"[A-Za-z0-9_-]+";id="session-1"$/', $header);
        $value = explode('"', $header)[1];
        static::assertSame('session-1', $manager->consume($value, 'session-1')->sessionIdentifier);
    }

    #[Test]
    public function theChallengeOutlivesTheBoundCookie(): void
    {
        // Given a challenge manager whose default TTL (300 s) is shorter than the cookie (600 s)
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $store = new InMemoryChallengeStore($clock);
        $manager = new ChallengeManager($store, $clock, 300);
        $response = new Response();
        (new ChallengePreprovisioner($manager, 600, 300))->preprovision($response, 'session-1');
        $value = explode('"', (string) $response->headers->get(SecureSessionHeaders::CHALLENGE))[1];

        // When the cookie has just expired
        $clock->set(new DateTimeImmutable('2026-01-01T00:10:01+00:00'));

        // Then the pre-provisioned challenge is still valid (until cookie lifetime + grace)
        static::assertNotNull($store->get($value));
        $clock->set(new DateTimeImmutable('2026-01-01T00:15:00+00:00'));
        static::assertNull($store->get($value));
    }

    #[Test]
    public function theNullPreprovisionerLeavesTheResponseUntouched(): void
    {
        // Given
        $response = new Response();

        // When
        (new NullChallengePreprovisioner())->preprovision($response, 'session-1');

        // Then
        static::assertFalse($response->headers->has(SecureSessionHeaders::CHALLENGE));
    }
}
