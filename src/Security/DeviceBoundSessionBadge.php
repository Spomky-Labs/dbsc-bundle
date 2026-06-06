<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security;

use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

/**
 * Opt-in marker added to a login passport to request device-bound registration, the analogue
 * of Symfony's RememberMeBadge.
 *
 * Like RememberMeBadge, its mere presence is not enough: it must also be enabled, which mirrors
 * the user ticking the "remember me" box (or an `always` policy). The registration header is
 * emitted only when the badge is present and enabled, so replacing remember-me with DBSC is a
 * one-badge swap that keeps the same opt-in condition.
 */
final class DeviceBoundSessionBadge implements BadgeInterface
{
    private bool $enabled = false;

    /**
     * Optional, application-defined value linking this registration to the authenticated session.
     * When set it is emitted in the `Secure-Session-Registration` header and the browser MUST echo
     * it back in the registration proof, where the bundle checks it matches.
     */
    private ?string $authorization = null;

    public function enable(): static
    {
        $this->enabled = true;

        return $this;
    }

    public function disable(): static
    {
        $this->enabled = false;

        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function setAuthorization(?string $authorization): static
    {
        $this->authorization = $authorization;

        return $this;
    }

    public function getAuthorization(): ?string
    {
        return $this->authorization;
    }

    public function isResolved(): bool
    {
        return true;
    }
}
