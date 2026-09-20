<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security;

use function is_array;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The token produced when a request is authenticated from the device-bound cookie.
 *
 * It extends {@see RememberMeToken} so the authentication trust resolver classifies it as
 * `IS_AUTHENTICATED_REMEMBERED` and never `IS_AUTHENTICATED_FULLY`: a device-bound
 * re-authentication is automatic, exactly like remember-me, so routes guarded by
 * `IS_AUTHENTICATED_FULLY` still require a fresh interactive login.
 *
 * {@see isDeviceBound()} is false when the session was registered with the `none` algorithm:
 * the cookie is refreshed without a device signature, so it carries no cookie-theft protection.
 * A voter or controller can require a device-bound session for sensitive actions.
 */
final class DeviceBoundSessionToken extends RememberMeToken
{
    public function __construct(
        UserInterface $user,
        string $firewallName,
        private bool $deviceBound = true,
    ) {
        parent::__construct($user, $firewallName);
    }

    public function isDeviceBound(): bool
    {
        return $this->deviceBound;
    }

    /**
     * @return array<int, mixed>
     */
    public function __serialize(): array
    {
        return [$this->deviceBound, parent::__serialize()];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        [$deviceBound, $parentData] = $data;
        $this->deviceBound = $deviceBound === true;
        parent::__unserialize(is_array($parentData) ? $parentData : []);
    }
}
