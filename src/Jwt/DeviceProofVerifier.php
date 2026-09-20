<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

use function hash_equals;
use function in_array;
use function is_array;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use JsonException;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use Throwable;

/**
 * Verifies the JWS proofs exchanged by the browser:
 *  - registration: the key is embedded in the proof and the signature proves possession;
 *  - refresh: the signature is checked against the previously stored device key.
 *
 * The `none` algorithm, when the firewall lists it, is verified through the same path with the
 * {@see DeviceProof::UNBOUND_KEY} placeholder. The key type is checked against the algorithm
 * before verification, so an unsigned proof never validates against a device-bound session and
 * a signed proof never validates against an unbound one.
 */
final readonly class DeviceProofVerifier implements DeviceProofVerifierInterface
{
    /**
     * The JWS algorithm of an unsigned proof, sent by a browser that could not bind a key.
     */
    private const ALGORITHM_NONE = 'none';

    private CompactSerializer $serializer;

    private JWSVerifier $verifier;

    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
    ) {
        $this->serializer = new CompactSerializer();
        $this->verifier = new JWSVerifier($this->algorithmProvider->getManager());
    }

    /**
     * Verifies a registration proof, returning the embedded device public key and claims. When
     * `$expectedAudience` is given and the proof carries an `aud` claim, the two must match.
     */
    public function verifyRegistration(string $token, ?string $expectedAudience = null): DeviceProof
    {
        [$jws, $claims] = $this->parse($token);

        $jwk = $this->extractEmbeddedKey($jws, $claims);
        $this->assertKeyMatchesAlgorithm($jws, $jwk);
        if (! $this->verifier->verifyWithKey($jws, new JWK($jwk), 0)) {
            throw InvalidProofException::badSignature();
        }

        $proof = new DeviceProof($jwk, $claims);
        $this->assertAudience($proof, $expectedAudience);

        return $proof;
    }

    /**
     * Verifies a refresh proof against the device key recorded at registration. When
     * `$expectedAudience` is given and the proof carries an `aud` claim, the two must match.
     *
     * @param array<string, mixed> $boundKey the stored device public key (JWK)
     */
    public function verifyRefresh(string $token, array $boundKey, ?string $expectedAudience = null): DeviceProof
    {
        [$jws, $claims] = $this->parse($token);

        $this->assertKeyMatchesAlgorithm($jws, $boundKey);
        if (! $this->verifier->verifyWithKey($jws, new JWK($boundKey), 0)) {
            throw InvalidProofException::badSignature();
        }

        $proof = new DeviceProof($boundKey, $claims);
        $this->assertAudience($proof, $expectedAudience);

        return $proof;
    }

    /**
     * Rejects a proof whose algorithm cannot be used with the key it is verified against: the JWS
     * verifier does not check key types itself, and the `none` algorithm accepts any key, so
     * without this an unsigned proof would validate against a device-bound session.
     *
     * @param array<string, mixed> $key
     */
    private function assertKeyMatchesAlgorithm(JWS $jws, array $key): void
    {
        $alg = $jws->getSignature(0)
            ->getProtectedHeader()['alg'] ?? null;
        $kty = $key['kty'] ?? null;
        if (! is_string($alg) || ! is_string($kty)) {
            throw InvalidProofException::keyAlgorithmMismatch(is_string($alg) ? $alg : 'none', is_string($kty) ? $kty : 'none');
        }

        $allowedKeyTypes = $this->algorithmProvider->getManager()
            ->get($alg)
            ->allowedKeyTypes();
        if (! in_array($kty, $allowedKeyTypes, true)) {
            throw InvalidProofException::keyAlgorithmMismatch($alg, $kty);
        }
    }

    /**
     * Rejects a proof whose `aud` claim, when present, does not match the endpoint it was sent to.
     * A missing claim is tolerated: not every browser sets it, and the single-use challenge already
     * binds the proof to a context.
     */
    private function assertAudience(DeviceProof $proof, ?string $expectedAudience): void
    {
        $audience = $proof->audience();
        if ($expectedAudience === null || $audience === null) {
            return;
        }

        if (! hash_equals($expectedAudience, $audience)) {
            throw InvalidProofException::audienceMismatch($expectedAudience, $audience);
        }
    }

    /**
     * @return array{0: JWS, 1: array<string, mixed>}
     */
    private function parse(string $token): array
    {
        if ($token === '') {
            throw InvalidProofException::malformed('empty token');
        }

        try {
            $jws = $this->serializer->unserialize($token);
        } catch (Throwable $e) {
            throw InvalidProofException::malformed($e->getMessage());
        }

        if ($jws->countSignatures() < 1) {
            throw InvalidProofException::malformed('no signature');
        }

        $header = $jws->getSignature(0)
            ->getProtectedHeader();

        $type = $header['typ'] ?? null;
        if ($type !== SecureSessionHeaders::JWT_TYPE) {
            throw InvalidProofException::unsupportedType(is_string($type) ? $type : 'none');
        }

        $alg = $header['alg'] ?? null;
        if (! is_string($alg) || ! in_array($alg, $this->algorithmProvider->getAllowedNames(), true)) {
            throw InvalidProofException::unsupportedAlgorithm(is_string($alg) ? $alg : 'none');
        }

        $payload = $jws->getPayload();
        if ($payload === null) {
            throw InvalidProofException::malformed('missing payload');
        }

        try {
            $claims = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw InvalidProofException::malformed('payload is not JSON: ' . $e->getMessage());
        }

        if (! is_array($claims)) {
            throw InvalidProofException::malformed('payload is not an object');
        }

        /** @var array<string, mixed> $claims */
        return [$jws, $claims];
    }

    /**
     * Extracts the public key the browser embedded in a registration proof. The DBSC specification
     * carries it as a `jwk` protected header; an earlier revision used a `key` payload claim,
     * still accepted as a fallback for compatibility.
     *
     * A proof made with the `none` algorithm (only reachable when the firewall lists it) embeds no
     * key, and the spec forbids a `jwk` header on it; the {@see DeviceProof::UNBOUND_KEY}
     * placeholder is returned so the session is recorded as not device-bound.
     *
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private function extractEmbeddedKey(JWS $jws, array $claims): array
    {
        $header = $jws->getSignature(0)
            ->getProtectedHeader();
        if (($header['alg'] ?? null) === self::ALGORITHM_NONE) {
            if (isset($header['jwk']) || isset($claims['key'])) {
                throw InvalidProofException::unexpectedKey();
            }

            return DeviceProof::UNBOUND_KEY;
        }

        $key = $header['jwk'] ?? $claims['key'] ?? null;
        if (! is_array($key) || $key === []) {
            throw InvalidProofException::missingKey();
        }

        /** @var array<string, mixed> $key */
        return $key;
    }
}
