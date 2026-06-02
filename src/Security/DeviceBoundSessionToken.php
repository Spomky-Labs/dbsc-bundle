<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security;

use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;

/**
 * The token produced when a request is authenticated from the device-bound cookie.
 *
 * It extends {@see RememberMeToken} so the authentication trust resolver classifies it as
 * `IS_AUTHENTICATED_REMEMBERED` and never `IS_AUTHENTICATED_FULLY`: a device-bound
 * re-authentication is automatic, exactly like remember-me, so routes guarded by
 * `IS_AUTHENTICATED_FULLY` still require a fresh interactive login.
 */
final class DeviceBoundSessionToken extends RememberMeToken
{
}
