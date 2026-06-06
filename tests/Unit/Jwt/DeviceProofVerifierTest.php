<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Jwt;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifier;

/**
 * @internal
 */
final class DeviceProofVerifierTest extends TestCase
{
    #[Test]
    public function itVerifiesARegistrationProofAndExtractsTheEmbeddedKey(): void
    {
        // Given a device key and a registration proof embedding its public part
        $key = JWKFactory::createECKey('P-256');
        $public = $key->toPublic()
            ->all();
        $token = $this->sign($key, [
            'jti' => 'challenge-abc',
            'aud' => '/dbsc/register',
            'key' => $public,
        ]);

        // When
        $proof = $this->verifier()
            ->verifyRegistration($token);

        // Then
        static::assertSame('challenge-abc', $proof->challenge());
        static::assertSame('EC', $proof->publicKeyJwk['kty']);
    }

    #[Test]
    public function itExtractsTheKeyFromTheJwkProtectedHeader(): void
    {
        // Given a registration proof that carries the public key in the `jwk` protected header
        // (the current draft) rather than the legacy `key` payload claim
        $key = JWKFactory::createECKey('P-256');
        $public = $key->toPublic()
            ->all();
        $token = $this->sign($key, [
            'jti' => 'challenge-jwk',
        ], 'dbsc+jwt', $public);

        // When
        $proof = $this->verifier()
            ->verifyRegistration($token);

        // Then
        static::assertSame('challenge-jwk', $proof->challenge());
        static::assertSame('EC', $proof->publicKeyJwk['kty']);
    }

    #[Test]
    public function itVerifiesARefreshProofAgainstTheStoredKey(): void
    {
        // Given
        $key = JWKFactory::createECKey('P-256');
        $public = $key->toPublic()
            ->all();
        $token = $this->sign($key, [
            'jti' => 'challenge-xyz',
            'aud' => '/dbsc/refresh',
        ]);

        // When
        $proof = $this->verifier()
            ->verifyRefresh($token, $public);

        // Then
        static::assertSame('challenge-xyz', $proof->challenge());
    }

    #[Test]
    public function itAcceptsAProofWhoseAudienceMatches(): void
    {
        // Given a refresh proof whose aud matches the endpoint
        $key = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
            'aud' => 'https://example.com/dbsc/refresh',
        ]);

        // When
        $proof = $this->verifier()
            ->verifyRefresh($token, $key->toPublic()->all(), 'https://example.com/dbsc/refresh');

        // Then
        static::assertSame('x', $proof->challenge());
    }

    #[Test]
    public function itRejectsAProofWhoseAudienceDiffers(): void
    {
        // Given a refresh proof minted for another endpoint
        $key = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
            'aud' => 'https://example.com/dbsc/register',
        ]);

        // Then
        $this->expectException(InvalidProofException::class);

        // When the expected audience differs
        $this->verifier()
            ->verifyRefresh($token, $key->toPublic()->all(), 'https://example.com/dbsc/refresh');
    }

    #[Test]
    public function itToleratesAProofWithoutAnAudienceClaim(): void
    {
        // Given a refresh proof that omits aud, while an audience is expected
        $key = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
        ]);

        // When
        $proof = $this->verifier()
            ->verifyRefresh($token, $key->toPublic()->all(), 'https://example.com/dbsc/refresh');

        // Then a missing claim is tolerated
        static::assertSame('x', $proof->challenge());
    }

    #[Test]
    public function itRejectsAProofSignedByAnotherKey(): void
    {
        // Given a proof signed by a different key than the stored one
        $key = JWKFactory::createECKey('P-256');
        $other = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
            'aud' => '/dbsc/refresh',
        ]);

        // Then
        $this->expectException(InvalidProofException::class);

        // When
        $this->verifier()
            ->verifyRefresh($token, $other->toPublic()->all());
    }

    #[Test]
    public function itRejectsAProofWithTheWrongType(): void
    {
        // Given a JWS whose typ is not dbsc+jwt
        $key = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
        ], 'JWT');

        // Then
        $this->expectException(InvalidProofException::class);

        // When
        $this->verifier()
            ->verifyRefresh($token, $key->toPublic()->all());
    }

    #[Test]
    public function itRejectsARegistrationProofWithoutAnEmbeddedKey(): void
    {
        // Given a registration proof missing the key claim
        $key = JWKFactory::createECKey('P-256');
        $token = $this->sign($key, [
            'jti' => 'x',
        ]);

        // Then
        $this->expectException(InvalidProofException::class);

        // When
        $this->verifier()
            ->verifyRegistration($token);
    }

    private function verifier(): DeviceProofVerifier
    {
        return new DeviceProofVerifier(new AlgorithmProvider([new ES256(), new RS256()], ['ES256', 'RS256']));
    }

    /**
     * @param array<string, mixed>      $payload
     * @param array<string, mixed>|null $jwk embedded in the `jwk` protected header when provided
     */
    private function sign(JWK $key, array $payload, string $type = 'dbsc+jwt', ?array $jwk = null): string
    {
        $header = [
            'alg' => 'ES256',
            'typ' => $type,
        ];
        if ($jwk !== null) {
            $header['jwk'] = $jwk;
        }

        $builder = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $jws = $builder->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR))
            ->addSignature($key, $header)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
