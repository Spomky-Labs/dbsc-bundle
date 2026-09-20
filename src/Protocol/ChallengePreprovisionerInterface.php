<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use Symfony\Component\HttpFoundation\Response;

/**
 * Optionally attaches the next refresh challenge to a successful registration or refresh
 * response. The browser caches a `Secure-Session-Challenge` received on any response and, on the
 * next refresh, sends the signed proof right away instead of an unsigned request answered by a
 * `403`, saving one round-trip per refresh.
 */
interface ChallengePreprovisionerInterface
{
    /**
     * Adds a `Secure-Session-Challenge` for `$sessionIdentifier` to `$response` when
     * pre-provisioning is enabled for the firewall, otherwise leaves the response untouched.
     */
    public function preprovision(Response $response, string $sessionIdentifier): void;
}
