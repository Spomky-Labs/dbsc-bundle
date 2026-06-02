<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\EventListener;

use const FILTER_VALIDATE_BOOL;
use function filter_var;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Enables a {@see DeviceBoundSessionBadge} carried by the login passport, mirroring Symfony's
 * CheckRememberMeConditionsListener: registration is requested either always, or when the
 * configured checkbox parameter is present and truthy in the request.
 */
final readonly class DeviceBoundSessionConditionsListener
{
    public function __construct(
        private bool $always,
        private string $checkbox,
    ) {
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $badge = $event->getPassport()
            ->getBadge(DeviceBoundSessionBadge::class);
        if (! $badge instanceof DeviceBoundSessionBadge) {
            return;
        }

        if (! $this->always && ! $this->isCheckboxTicked($event->getRequest())) {
            return;
        }

        $badge->enable();
    }

    private function isCheckboxTicked(Request $request): bool
    {
        $value = $request->request->get($this->checkbox, $request->query->get($this->checkbox));

        return filter_var($value, FILTER_VALIDATE_BOOL) === true;
    }
}
