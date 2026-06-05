<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\DbscBundle\Session\SessionBinding;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exercises the full-replacement mode: a firewall configured with `device_bound_session`
 * authenticates the request from the device-bound cookie alone, with no session cookie.
 *
 * @internal
 */
final class FullReplacementFirewallTest extends WebTestCase
{
    private const COOKIE = 'dbsc_session';

    #[Test]
    public function itAuthenticatesAProtectedRequestFromTheBoundCookie(): void
    {
        // Given a registered binding whose current cookie token is "tok-1" for user "alice"
        $client = self::createClient();
        $this->seedBinding('tok-1', 'alice');

        // When the bound cookie is presented
        $client->getCookieJar()
            ->set(new Cookie(self::COOKIE, 'tok-1'));
        $client->request('GET', '/secured');

        // Then the user is authenticated without any session cookie
        static::assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        static::assertSame('hello alice', $client->getResponse()->getContent());
    }

    #[Test]
    public function itGrantsRememberedButNotFullAuthentication(): void
    {
        // Given a device-bound (remembered) session
        $client = self::createClient();
        $this->seedBinding('tok-1', 'alice');
        $client->getCookieJar()
            ->set(new Cookie(self::COOKIE, 'tok-1'));

        // When a sensitive area requires IS_AUTHENTICATED_FULLY
        $client->request('GET', '/secured/fully');

        // Then a fresh interactive login is required (remembered is not full authentication)
        static::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    #[Test]
    public function itDeniesAProtectedRequestWithoutABoundCookie(): void
    {
        // Given
        $client = self::createClient();

        // When no bound cookie is presented
        $client->request('GET', '/secured');

        // Then access is denied (no long-lived fallback)
        static::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    #[Test]
    public function itDeniesARevokedOrStaleCookieToken(): void
    {
        // Given a binding that has since rotated its token away from "old-token"
        $client = self::createClient();
        $this->seedBinding('current-token', 'alice');

        // When an out-of-date cookie is presented
        $client->getCookieJar()
            ->set(new Cookie(self::COOKIE, 'old-token'));
        $client->request('GET', '/secured');

        // Then access is denied
        static::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    private function seedBinding(string $cookieToken, string $userIdentifier): void
    {
        /** @var SessionBindingRepository $repository */
        $repository = static::getContainer()->get('dbsc.binding_repository.secured');
        $repository->save(new SessionBinding('sid-' . $cookieToken, [
            'kty' => 'EC',
        ], $userIdentifier, 1_000, $cookieToken));
    }
}
