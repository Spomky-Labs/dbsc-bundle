<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Exception\UnknownSessionException;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifierInterface;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;

/**
 * Handles the refresh step: verifies the signed proof against the stored device key,
 * consumes the challenge and mints a fresh bound cookie.
 */
final readonly class RefreshHandler implements RefreshHandlerInterface
{
    public function __construct(
        private DeviceProofVerifierInterface $verifier,
        private ChallengeManagerInterface $challengeManager,
        private SessionBindingRepository $bindings,
        private SessionConfigFactoryInterface $configFactory,
        private TokenGeneratorInterface $tokens,
    ) {
    }

    public function refresh(string $sessionIdentifier, string $proofToken, string $origin): IssuedSession
    {
        $binding = $this->bindings->findBySessionIdentifier($sessionIdentifier);
        if ($binding === null) {
            throw UnknownSessionException::forIdentifier($sessionIdentifier);
        }

        $proof = $this->verifier->verifyRefresh($proofToken, $binding->publicKeyJwk);
        $this->challengeManager->consume($proof->challenge(), $sessionIdentifier);

        $cookieToken = $this->tokens->generate();
        $this->bindings->save($binding->withCookieToken($cookieToken));

        return new IssuedSession(
            $sessionIdentifier,
            $cookieToken,
            $this->configFactory->create($sessionIdentifier, $origin),
        );
    }
}
