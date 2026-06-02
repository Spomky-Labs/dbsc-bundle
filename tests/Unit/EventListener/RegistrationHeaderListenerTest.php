<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\EventListener;

use DateTimeImmutable;
use Jose\Component\Signature\Algorithm\ES256;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\EventListener\RegistrationHeaderListener;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use SpomkyLabs\DbscBundle\Tests\FixedClock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * @internal
 */
final class RegistrationHeaderListenerTest extends TestCase
{
    #[Test]
    public function itEmitsTheRegistrationHeaderWhenTheBadgeIsEnabled(): void
    {
        // Given a login passport whose device-bound badge is enabled
        $response = new Response();
        $passport = new SelfValidatingPassport(new UserBadge('alice'));
        $passport->addBadge((new DeviceBoundSessionBadge())->enable());

        // When
        $this->listener()
            ->onLoginSuccess($this->event($passport, $response));

        // Then the browser is asked to register a device-bound key
        static::assertTrue($response->headers->has(SecureSessionHeaders::REGISTRATION));
        static::assertStringContainsString(
            'challenge=',
            (string) $response->headers->get(SecureSessionHeaders::REGISTRATION)
        );
    }

    #[Test]
    public function itDoesNotEmitWhenTheBadgeIsPresentButDisabled(): void
    {
        // Given a login passport whose badge was not enabled by the conditions
        $response = new Response();
        $passport = new SelfValidatingPassport(new UserBadge('alice'));
        $passport->addBadge(new DeviceBoundSessionBadge());

        // When
        $this->listener()
            ->onLoginSuccess($this->event($passport, $response));

        // Then no registration header is emitted
        static::assertFalse($response->headers->has(SecureSessionHeaders::REGISTRATION));
    }

    #[Test]
    public function itDoesNotEmitWithoutTheBadge(): void
    {
        // Given a login passport that did not opt in
        $response = new Response();
        $passport = new SelfValidatingPassport(new UserBadge('alice'));

        // When
        $this->listener()
            ->onLoginSuccess($this->event($passport, $response));

        // Then no registration header is emitted
        static::assertFalse($response->headers->has(SecureSessionHeaders::REGISTRATION));
    }

    private function listener(): RegistrationHeaderListener
    {
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $challengeManager = new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300);
        $algorithmProvider = new AlgorithmProvider([new ES256()], ['ES256']);

        return new RegistrationHeaderListener($challengeManager, $algorithmProvider, '/dbsc/register');
    }

    private function event(Passport $passport, Response $response): LoginSuccessEvent
    {
        $event = static::createStub(LoginSuccessEvent::class);
        $event->method('getPassport')
            ->willReturn($passport);
        $event->method('getResponse')
            ->willReturn($response);

        return $event;
    }
}
