<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

/**
 * Issues and validates single-use challenges.
 */
interface ChallengeManagerInterface
{
    /**
     * Issues a single-use challenge, recording what the resulting proof will be checked against:
     * the session it belongs to (refresh), the `authorization` value it must echo and the
     * `provider_key` thumbprint its embedded key must hash to (registration).
     */
    public function issue(
        ?string $sessionIdentifier = null,
        ?string $authorization = null,
        ?string $providerKey = null,
    ): Challenge;

    /**
     * Validates and consumes a presented challenge so it cannot be replayed, returning the
     * consumed challenge so the caller can inspect what was bound to it (session, authorization).
     */
    public function consume(string $value, ?string $expectedSessionIdentifier = null): Challenge;
}
