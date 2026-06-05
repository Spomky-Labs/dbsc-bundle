<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security;

use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Authenticates a request from the device-bound cookie, fully replacing the long-lived
 * session cookie. The cookie value is the rotating token recorded in the session binding;
 * possession alone is not enough to keep the session alive, because the browser must
 * periodically re-prove possession of the device key through the refresh endpoint to obtain
 * the next token.
 *
 * This is agnostic to how the user originally logged in: the binding stores the user
 * identifier captured at registration (set by whatever authenticator handled the login:
 * password, WebAuthn, SSO…), and the user is reloaded from the firewall's user provider.
 */
final class DeviceBoundSessionAuthenticator extends AbstractAuthenticator
{
    /**
     * @param UserProviderInterface<UserInterface> $userProvider
     */
    public function __construct(
        private readonly SessionBindingRepository $bindings,
        private readonly UserProviderInterface $userProvider,
        private readonly string $cookieName,
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    /**
     * Lazy, remember-me-like: false when a token is already established for the request (e.g.
     * restored from the session) so a live full session keeps IS_AUTHENTICATED_FULLY; null (lazy)
     * when only the bound cookie is present, authenticating when nothing else did.
     */
    public function supports(Request $request): ?bool
    {
        if ($this->tokenStorage->getToken() !== null) {
            return false;
        }

        return $request->cookies->has($this->cookieName) ? null : false;
    }

    public function authenticate(Request $request): Passport
    {
        $token = (string) $request->cookies->get($this->cookieName, '');
        $binding = $token === '' ? null : $this->bindings->findByCookieToken($token);
        if ($binding === null || $binding->userIdentifier === null) {
            throw new CustomUserMessageAuthenticationException('Invalid device-bound session.');
        }

        return new SelfValidatingPassport(
            new UserBadge($binding->userIdentifier, $this->userProvider->loadUserByIdentifier(...)),
        );
    }

    /**
     * Produces a remembered-level token: a device-bound re-authentication grants
     * IS_AUTHENTICATED_REMEMBERED, never IS_AUTHENTICATED_FULLY.
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new DeviceBoundSessionToken($passport->getUser(), $firewallName);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): null
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): null
    {
        return null;
    }
}
