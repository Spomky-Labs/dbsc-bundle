<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\EventListener;

use function implode;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProviderInterface;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use function sprintf;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Emits the `Secure-Session-Registration` header on the login response, asking a supporting
 * browser to register a device-bound key. Browsers that do not understand the header ignore
 * it, leaving the login flow unchanged.
 *
 * The header is emitted only when the login passport carries a {@see DeviceBoundSessionBadge},
 * the analogue of opting in with a RememberMeBadge. A device-bound re-authentication never
 * carries it, so registration is not re-triggered on every request.
 */
final readonly class RegistrationHeaderListener
{
    public function __construct(
        private ChallengeManagerInterface $challengeManager,
        private AlgorithmProviderInterface $algorithmProvider,
        private string $registrationPath,
    ) {
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $badge = $event->getPassport()
            ->getBadge(DeviceBoundSessionBadge::class);
        if (! $badge instanceof DeviceBoundSessionBadge || ! $badge->isEnabled()) {
            return;
        }

        $response = $event->getResponse();
        if ($response === null) {
            return;
        }

        $challenge = $this->challengeManager->issue();
        $algorithms = implode(' ', $this->algorithmProvider->getAllowedNames());

        $response->headers->set(
            SecureSessionHeaders::REGISTRATION,
            sprintf('(%s);challenge="%s";path="%s"', $algorithms, $challenge->value, $this->registrationPath),
        );
    }
}
