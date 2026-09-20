<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

use function is_string;

/**
 * The validated content of a DBSC proof JWS: the device public key and the relevant claims.
 *
 * @phpstan-type Jwk array<string, mixed>
 */
final readonly class DeviceProof
{
    /**
     * The placeholder key recorded for a session registered with the `none` algorithm: the
     * browser could not bind a key, the proof is unsigned and the session is not device-bound.
     * It is the JWK the `none` JWS algorithm expects, so the same verifier path applies.
     */
    public const UNBOUND_KEY = [
        'kty' => 'none',
    ];

    /**
     * @param Jwk                  $publicKeyJwk the device public key (embedded on registration, stored thereafter)
     * @param array<string, mixed> $claims       the decoded JWS payload
     */
    public function __construct(
        public array $publicKeyJwk,
        public array $claims,
    ) {
    }

    /**
     * False for a proof made with the `none` algorithm, i.e. a session that is not bound to a
     * device key.
     */
    public function isDeviceBound(): bool
    {
        return ($this->publicKeyJwk['kty'] ?? null) !== self::UNBOUND_KEY['kty'];
    }

    /**
     * The challenge the browser signed (`jti` claim).
     */
    public function challenge(): string
    {
        $jti = $this->claims['jti'] ?? '';

        return is_string($jti) ? $jti : '';
    }

    /**
     * Optional opaque value linking the registration to the authenticated session,
     * passed back from the `Secure-Session-Registration` header (`authorization` claim).
     */
    public function authorization(): ?string
    {
        $authorization = $this->claims['authorization'] ?? null;

        return is_string($authorization) ? $authorization : null;
    }

    /**
     * The endpoint the proof was minted for (`aud` claim), or null when the browser omitted it.
     */
    public function audience(): ?string
    {
        $audience = $this->claims['aud'] ?? null;

        return is_string($audience) ? $audience : null;
    }
}
