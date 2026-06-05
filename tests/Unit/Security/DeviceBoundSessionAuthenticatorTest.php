<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionAuthenticator;
use SpomkyLabs\DbscBundle\Session\InMemorySessionBindingRepository;
use SpomkyLabs\DbscBundle\Session\SessionBinding;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @internal
 */
final class DeviceBoundSessionAuthenticatorTest extends TestCase
{
    private const COOKIE = '__Host-Http-dbsc_session';

    #[Test]
    public function itLazilySupportsTheBoundCookieWhenNothingElseAuthenticated(): void
    {
        // Given no token is already established for the request
        $authenticator = $this->createAuthenticator(new InMemorySessionBindingRepository());

        // Then the bound cookie is supported lazily (null), and an absent cookie is skipped
        static::assertNull($authenticator->supports($this->requestWithCookie('whatever')));
        static::assertFalse($authenticator->supports(new Request()));
    }

    #[Test]
    public function itDoesNotOverrideATokenAlreadyEstablished(): void
    {
        // Given a token already established for the request (e.g. restored from the session)
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('alice', null), 'main'));
        $authenticator = $this->createAuthenticator(new InMemorySessionBindingRepository(), $tokenStorage);

        // Then the device-bound authenticator stays out of the way even with the cookie present
        static::assertFalse($authenticator->supports($this->requestWithCookie('whatever')));
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

    private function createAuthenticator(
        InMemorySessionBindingRepository $repository,
        ?TokenStorageInterface $tokenStorage = null
    ): DeviceBoundSessionAuthenticator {
        $provider = static::createStub(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')
            ->willReturn(new InMemoryUser('alice', null));

        return new DeviceBoundSessionAuthenticator(
            $repository,
            $provider,
            self::COOKIE,
            $tokenStorage ?? new TokenStorage(),
        );
    }

    private function requestWithCookie(string $value): Request
    {
        return new Request([], [], [], [
            self::COOKIE => $value,
        ]);
    }
}
