<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

/**
 * Verifies the JWS proofs exchanged by the browser during registration and refresh.
 */
interface DeviceProofVerifierInterface
{
    /**
     * Verifies a registration proof, returning the embedded device public key and claims.
     */
    public function verifyRegistration(string $token): DeviceProof;

    /**
     * Verifies a refresh proof against the device key recorded at registration.
     *
     * @param array<string, mixed> $boundKey the stored device public key (JWK)
     */
    public function verifyRefresh(string $token, array $boundKey): DeviceProof;
}
