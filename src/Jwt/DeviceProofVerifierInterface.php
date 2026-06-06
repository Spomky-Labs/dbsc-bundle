<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

/**
 * Verifies the JWS proofs exchanged by the browser during registration and refresh.
 */
interface DeviceProofVerifierInterface
{
    /**
     * Verifies a registration proof, returning the embedded device public key and claims. When
     * `$expectedAudience` is given and the proof carries an `aud` claim, the two must match.
     */
    public function verifyRegistration(string $token, ?string $expectedAudience = null): DeviceProof;

    /**
     * Verifies a refresh proof against the device key recorded at registration. When
     * `$expectedAudience` is given and the proof carries an `aud` claim, the two must match.
     *
     * @param array<string, mixed> $boundKey the stored device public key (JWK)
     */
    public function verifyRefresh(string $token, array $boundKey, ?string $expectedAudience = null): DeviceProof;
}
