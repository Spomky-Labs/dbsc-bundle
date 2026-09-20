<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Session;

use SpomkyLabs\DbscBundle\Jwt\DeviceProof;

/**
 * The association between a DBSC session and the device-bound public key that must sign
 * every refresh. This is the record an attacker cannot forge without the TPM-held private key.
 *
 * A session registered with the `none` algorithm (allowed only when `none` is listed in the
 * firewall's `algorithms`) records the {@see DeviceProof::UNBOUND_KEY} placeholder instead: it
 * gets the session-management semantics of DBSC but no cookie-theft protection, and
 * {@see isDeviceBound()} lets the application tell the two apart.
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
     * False for a session registered with the `none` algorithm: its refreshes are unsigned, so a
     * stolen cookie can be refreshed from anywhere. Applications may require a device-bound
     * session for sensitive actions.
     */
    public function isDeviceBound(): bool
    {
        return ($this->publicKeyJwk['kty'] ?? null) !== DeviceProof::UNBOUND_KEY['kty'];
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
