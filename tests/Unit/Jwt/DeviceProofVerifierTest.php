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
     * @param array<string, mixed> $payload
     */
    private function sign(JWK $key, array $payload, string $type = 'dbsc+jwt'): string
    {
        $builder = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $jws = $builder->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'ES256',
                'typ' => $type,
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
