<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

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
 */
final readonly class DeviceProofVerifier implements DeviceProofVerifierInterface
{
    private CompactSerializer $serializer;

    private JWSVerifier $verifier;

    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
    ) {
        $this->serializer = new CompactSerializer();
        $this->verifier = new JWSVerifier($this->algorithmProvider->getManager());
    }

    /**
     * Verifies a registration proof, returning the embedded device public key and claims.
     */
    public function verifyRegistration(string $token): DeviceProof
    {
        [$jws, $claims] = $this->parse($token);

        $jwk = $this->extractEmbeddedKey($jws, $claims);
        if (! $this->verifier->verifyWithKey($jws, new JWK($jwk), 0)) {
            throw InvalidProofException::badSignature();
        }

        return new DeviceProof($jwk, $claims);
    }

    /**
     * Verifies a refresh proof against the device key recorded at registration.
     *
     * @param array<string, mixed> $boundKey the stored device public key (JWK)
     */
    public function verifyRefresh(string $token, array $boundKey): DeviceProof
    {
        [$jws, $claims] = $this->parse($token);

        if (! $this->verifier->verifyWithKey($jws, new JWK($boundKey), 0)) {
            throw InvalidProofException::badSignature();
        }

        return new DeviceProof($boundKey, $claims);
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
     * Extracts the public key the browser embedded in a registration proof. The DBSC draft
     * carries it as a `key` claim in the payload; the `jwk` protected header is also accepted.
     *
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private function extractEmbeddedKey(JWS $jws, array $claims): array
    {
        $key = $claims['key'] ?? $jws->getSignature(0)->getProtectedHeader()['jwk'] ?? null;
        if (! is_array($key) || $key === []) {
            throw InvalidProofException::missingKey();
        }

        /** @var array<string, mixed> $key */
        return $key;
    }
}
