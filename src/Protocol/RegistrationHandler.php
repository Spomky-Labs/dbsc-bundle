<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use Psr\Clock\ClockInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifierInterface;
use SpomkyLabs\DbscBundle\Session\SessionBinding;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;

/**
 * Handles the registration (StartSession) step: verifies the device key, consumes the
 * login challenge, records the binding and issues the first bound cookie.
 */
final readonly class RegistrationHandler implements RegistrationHandlerInterface
{
    public function __construct(
        private DeviceProofVerifierInterface $verifier,
        private ChallengeManagerInterface $challengeManager,
        private SessionBindingRepository $bindings,
        private SessionConfigFactoryInterface $configFactory,
        private TokenGeneratorInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    public function register(string $proofToken, ?string $userIdentifier, string $origin): IssuedSession
    {
        $proof = $this->verifier->verifyRegistration($proofToken);
        $this->challengeManager->consume($proof->challenge());

        $sessionIdentifier = $this->tokens->generate();
        $cookieToken = $this->tokens->generate();
        $this->bindings->save(new SessionBinding(
            $sessionIdentifier,
            $proof->publicKeyJwk,
            $userIdentifier,
            $this->clock->now()
                ->getTimestamp(),
            $cookieToken,
        ));

        return new IssuedSession(
            $sessionIdentifier,
            $cookieToken,
            $this->configFactory->create($sessionIdentifier, $origin),
        );
    }
}
