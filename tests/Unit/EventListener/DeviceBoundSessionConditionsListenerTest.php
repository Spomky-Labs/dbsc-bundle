<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\EventListener;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\EventListener\DeviceBoundSessionConditionsListener;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * @internal
 */
final class DeviceBoundSessionConditionsListenerTest extends TestCase
{
    #[Test]
    public function itEnablesTheBadgeWhenAlwaysIsTrue(): void
    {
        // Given an always policy and a passport carrying a (disabled) badge
        $badge = new DeviceBoundSessionBadge();
        $listener = new DeviceBoundSessionConditionsListener(true, '_device_bound_session');

        // When
        $listener->onLoginSuccess($this->event($this->passport($badge), new Request()));

        // Then
        static::assertTrue($badge->isEnabled());
    }

    #[Test]
    public function itEnablesTheBadgeWhenTheCheckboxParameterIsTruthy(): void
    {
        // Given the checkbox policy and a request that ticked the box
        $badge = new DeviceBoundSessionBadge();
        $listener = new DeviceBoundSessionConditionsListener(false, '_device_bound_session');
        $request = Request::create('/login', 'POST', [
            '_device_bound_session' => '1',
        ]);

        // When
        $listener->onLoginSuccess($this->event($this->passport($badge), $request));

        // Then
        static::assertTrue($badge->isEnabled());
    }

    #[Test]
    public function itLeavesTheBadgeDisabledWhenTheCheckboxIsAbsent(): void
    {
        // Given the checkbox policy and a request without the parameter
        $badge = new DeviceBoundSessionBadge();
        $listener = new DeviceBoundSessionConditionsListener(false, '_device_bound_session');

        // When
        $listener->onLoginSuccess($this->event($this->passport($badge), new Request()));

        // Then
        static::assertFalse($badge->isEnabled());
    }

    #[Test]
    public function itIgnoresAPassportWithoutTheBadge(): void
    {
        // Given a passport with no device-bound badge
        $listener = new DeviceBoundSessionConditionsListener(true, '_device_bound_session');
        $passport = new SelfValidatingPassport(new UserBadge('alice'));

        // When / Then (no error)
        $listener->onLoginSuccess($this->event($passport, new Request()));
        static::assertFalse($passport->hasBadge(DeviceBoundSessionBadge::class));
    }

    private function passport(DeviceBoundSessionBadge $badge): Passport
    {
        return new SelfValidatingPassport(new UserBadge('alice'), [$badge]);
    }

    private function event(Passport $passport, Request $request): LoginSuccessEvent
    {
        $event = static::createStub(LoginSuccessEvent::class);
        $event->method('getPassport')
            ->willReturn($passport);
        $event->method('getRequest')
            ->willReturn($request);

        return $event;
    }
}
