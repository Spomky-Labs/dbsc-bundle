<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests;

use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Minimal interactive authenticator used to exercise the real login flow (the firewall-scoped
 * LoginSuccessEvent dispatch) in functional tests.
 *
 * @internal
 */
final class LoginTestAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): bool
    {
        return $request->getPathInfo() === '/test-login';
    }

    public function authenticate(Request $request): Passport
    {
        return new SelfValidatingPassport(new UserBadge('alice'), [new DeviceBoundSessionBadge()]);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        return new Response('logged in');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new Response('login failed', Response::HTTP_UNAUTHORIZED);
    }
}
