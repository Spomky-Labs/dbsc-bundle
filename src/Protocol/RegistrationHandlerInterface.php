<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * Handles the registration (StartSession) step of the DBSC protocol.
 */
interface RegistrationHandlerInterface
{
    public function register(
        string $proofToken,
        ?string $userIdentifier,
        string $origin,
        ?string $expectedAudience = null,
    ): IssuedSession;
}
