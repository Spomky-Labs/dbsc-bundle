<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issues a challenge bound to the session and sets it on the response, with a lifetime that
 * outlives the bound cookie: the browser only uses the cached challenge when the cookie expires,
 * so a challenge that expired before the cookie would only send it back to the `403` path.
 */
final readonly class ChallengePreprovisioner implements ChallengePreprovisionerInterface
{
    /**
     * @param int $cookieLifetime lifetime of the bound cookie, in seconds
     * @param int $grace          extra seconds granted beyond the cookie lifetime, so a refresh
     *                            started right at expiry still finds its challenge valid
     */
    public function __construct(
        private ChallengeManagerInterface $challengeManager,
        private int $cookieLifetime,
        private int $grace,
    ) {
    }

    public function preprovision(Response $response, string $sessionIdentifier): void
    {
        $challenge = $this->challengeManager->issue($sessionIdentifier, null, $this->cookieLifetime + $this->grace);

        $response->headers->set(
            SecureSessionHeaders::CHALLENGE,
            SecureSessionHeaders::challengeValue($challenge->value, $sessionIdentifier),
        );
    }
}
