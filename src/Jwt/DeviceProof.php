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
     * @param Jwk                  $publicKeyJwk the device public key (embedded on registration, stored thereafter)
     * @param array<string, mixed> $claims       the decoded JWS payload
     */
    public function __construct(
        public array $publicKeyJwk,
        public array $claims,
    ) {
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
