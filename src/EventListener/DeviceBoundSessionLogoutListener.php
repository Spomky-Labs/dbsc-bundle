<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\EventListener;

use SpomkyLabs\DbscBundle\Http\BoundCookieFactoryInterface;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Clears the device-bound credential on logout, the analogue of remember-me clearing its cookie
 * and deleting its persistent token: the binding is deleted from the repository so the cookie can
 * no longer be refreshed (the refresh endpoint then terminates the session), and the cookie is
 * cleared from the browser. Wired automatically per firewall by the security factory.
 */
final readonly class DeviceBoundSessionLogoutListener
{
    public function __construct(
        private SessionBindingRepository $bindings,
        private BoundCookieFactoryInterface $cookieFactory,
    ) {
    }

    public function onLogout(LogoutEvent $event): void
    {
        $token = (string) $event->getRequest()
            ->cookies->get($this->cookieFactory->name(), '');
        if ($token !== '') {
            $binding = $this->bindings->findByCookieToken($token);
            if ($binding !== null) {
                $this->bindings->deleteBySessionIdentifier($binding->sessionIdentifier);
            }
        }

        $event->getResponse()
            ?->headers->setCookie($this->cookieFactory->clear());
    }
}
