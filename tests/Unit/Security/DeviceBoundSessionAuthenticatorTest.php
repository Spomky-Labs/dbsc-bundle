<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionAuthenticator;
use SpomkyLabs\DbscBundle\Session\InMemorySessionBindingRepository;
use SpomkyLabs\DbscBundle\Session\SessionBinding;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @internal
 */
final class DeviceBoundSessionAuthenticatorTest extends TestCase
{
    private const COOKIE = '__Host-dbsc_session';

    #[Test]
    public function itSupportsRequestsCarryingTheBoundCookie(): void
    {
        // Given
        $authenticator = $this->createAuthenticator(new InMemorySessionBindingRepository());

        // Then
        static::assertTrue($authenticator->supports($this->requestWithCookie('whatever')));
        static::assertFalse($authenticator->supports(new Request()));
    }

    #[Test]
    public function itAuthenticatesTheUserBoundToTheCookieToken(): void
    {
        // Given a binding whose rotating cookie token is "tok-1", regardless of the original login
        $repository = new InMemorySessionBindingRepository();
        $repository->save(new SessionBinding('sid', [
            'kty' => 'EC',
        ], 'alice', 1_000, 'tok-1'));
        $authenticator = $this->createAuthenticator($repository);

        // When
        $passport = $authenticator->authenticate($this->requestWithCookie('tok-1'));

        // Then the user bound to the cookie is resolved from the firewall's provider
        static::assertSame('alice', $passport->getUser()->getUserIdentifier());
    }

    #[Test]
    public function itRejectsAnUnknownCookieToken(): void
    {
        // Given
        $authenticator = $this->createAuthenticator(new InMemorySessionBindingRepository());

        // Then
        $this->expectException(AuthenticationException::class);

        // When
        $authenticator->authenticate($this->requestWithCookie('unknown'));
    }

    private function createAuthenticator(InMemorySessionBindingRepository $repository): DeviceBoundSessionAuthenticator
    {
        $provider = static::createStub(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')
            ->willReturn(new InMemoryUser('alice', null));

        return new DeviceBoundSessionAuthenticator($repository, $provider, self::COOKIE);
    }

    private function requestWithCookie(string $value): Request
    {
        return new Request([], [], [], [
            self::COOKIE => $value,
        ]);
    }
}
