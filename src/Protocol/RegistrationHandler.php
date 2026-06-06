<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use function hash_equals;
use Psr\Clock\ClockInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
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

    /**
     * Verifies the registration proof, consumes the login challenge, records the binding and
     * issues the first bound cookie. When an `authorization` value was bound to the challenge, the
     * proof must echo it back unchanged (spec § 9.10) or it is rejected.
     */
    public function register(string $proofToken, ?string $userIdentifier, string $origin): IssuedSession
    {
        $proof = $this->verifier->verifyRegistration($proofToken);
        $challenge = $this->challengeManager->consume($proof->challenge());

        $expectedAuthorization = $challenge->authorization;
        if ($expectedAuthorization !== null
            && ! hash_equals($expectedAuthorization, $proof->authorization() ?? '')
        ) {
            throw InvalidProofException::authorizationMismatch();
        }

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
