<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use Symfony\Component\HttpFoundation\Response;

/**
 * Default when pre-provisioning is disabled: every refresh starts with the unsigned request and
 * its `403` challenge.
 */
final readonly class NullChallengePreprovisioner implements ChallengePreprovisionerInterface
{
    public function preprovision(Response $response, string $sessionIdentifier): void
    {
    }
}
