<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Session;

/**
 * The association between a DBSC session and the device-bound public key that must sign
 * every refresh. This is the record an attacker cannot forge without the TPM-held private key.
 *
 * @phpstan-type Jwk array<string, mixed>
 */
final readonly class SessionBinding
{
    /**
     * @param Jwk $publicKeyJwk the device public key, as a JWK array
     */
    public function __construct(
        public string $sessionIdentifier,
        public array $publicKeyJwk,
        public ?string $userIdentifier = null,
        public ?int $createdAt = null,
        public ?string $cookieToken = null,
    ) {
    }

    /**
     * Returns a copy of the binding with a rotated bound-cookie token. Called on every
     * refresh so a captured cookie cannot be replayed once the next one is issued.
     */
    public function withCookieToken(string $cookieToken): self
    {
        return new self(
            $this->sessionIdentifier,
            $this->publicKeyJwk,
            $this->userIdentifier,
            $this->createdAt,
            $cookieToken
        );
    }
}
