<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use Psr\Clock\ClockInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Exception\SessionExpiredException;
use SpomkyLabs\DbscBundle\Exception\UnknownSessionException;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifierInterface;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;

/**
 * Handles the refresh step: verifies the signed proof against the stored device key, consumes
 * the challenge and mints a fresh bound cookie. The bound cookie lifetime governs how often this
 * runs; the optional session lifetime governs how long the credential itself stays valid (the
 * durable, remember-me-like part), independently of the short cookie.
 */
final readonly class RefreshHandler implements RefreshHandlerInterface
{
    public function __construct(
        private DeviceProofVerifierInterface $verifier,
        private ChallengeManagerInterface $challengeManager,
        private SessionBindingRepository $bindings,
        private SessionConfigFactoryInterface $configFactory,
        private TokenGeneratorInterface $tokens,
        private ClockInterface $clock,
        private ?int $sessionLifetime = null,
    ) {
    }

    public function refresh(
        string $sessionIdentifier,
        string $proofToken,
        string $origin,
        ?string $expectedAudience = null,
    ): IssuedSession {
        $binding = $this->bindings->findBySessionIdentifier($sessionIdentifier);
        if ($binding === null) {
            throw UnknownSessionException::forIdentifier($sessionIdentifier);
        }

        if ($this->sessionLifetime !== null
            && $binding->createdAt !== null
            && $this->clock->now()
                ->getTimestamp() >= $binding->createdAt + $this->sessionLifetime
        ) {
            throw SessionExpiredException::forIdentifier($sessionIdentifier);
        }

        $proof = $this->verifier->verifyRefresh($proofToken, $binding->publicKeyJwk, $expectedAudience);
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
