<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * Handles the refresh step of the DBSC protocol.
 */
interface RefreshHandlerInterface
{
    public function refresh(
        string $sessionIdentifier,
        string $proofToken,
        string $origin,
        ?string $expectedAudience = null,
    ): IssuedSession;
}
