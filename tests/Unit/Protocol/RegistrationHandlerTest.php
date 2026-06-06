<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Protocol;

use DateTimeImmutable;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifier;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandler;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactory;
use SpomkyLabs\DbscBundle\Protocol\TokenGenerator;
use SpomkyLabs\DbscBundle\Session\InMemorySessionBindingRepository;
use SpomkyLabs\DbscBundle\Tests\FixedClock;

/**
 * @internal
 */
final class RegistrationHandlerTest extends TestCase
{
    private FixedClock $clock;

    private ChallengeManager $challengeManager;

    private InMemorySessionBindingRepository $bindings;

    protected function setUp(): void
    {
        $this->clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $this->challengeManager = new ChallengeManager(new InMemoryChallengeStore($this->clock), $this->clock, 300);
        $this->bindings = new InMemorySessionBindingRepository();
    }

    #[Test]
    public function itRegistersWhenTheProofEchoesTheExpectedAuthorization(): void
    {
        // Given a challenge issued with an authorization value, and a proof echoing it back
        $challenge = $this->challengeManager->issue(null, 'auth-token-123');
        $key = JWKFactory::createECKey('P-256');
        $proof = $this->sign($key, [
            'jti' => $challenge->value,
            'authorization' => 'auth-token-123',
        ]);

        // When
        $issued = $this->handler()
            ->register($proof, 'alice', 'https://example.com');

        // Then a binding is recorded for the issued session
        static::assertNotNull($this->bindings->findBySessionIdentifier($issued->sessionIdentifier));
    }

    #[Test]
    public function itRejectsAProofThatDoesNotEchoTheAuthorization(): void
    {
        // Given a challenge bound to an authorization value
        $challenge = $this->challengeManager->issue(null, 'auth-token-123');
        $key = JWKFactory::createECKey('P-256');
        $proof = $this->sign($key, [
            'jti' => $challenge->value,
            'authorization' => 'tampered',
        ]);

        // Then
        $this->expectException(InvalidProofException::class);

        // When the echoed authorization does not match
        $this->handler()
            ->register($proof, 'alice', 'https://example.com');
    }

    #[Test]
    public function itRegistersWhenNoAuthorizationWasRequested(): void
    {
        // Given a plain challenge (no authorization) and a proof without one
        $challenge = $this->challengeManager->issue();
        $key = JWKFactory::createECKey('P-256');
        $proof = $this->sign($key, [
            'jti' => $challenge->value,
        ]);

        // When
        $issued = $this->handler()
            ->register($proof, 'alice', 'https://example.com');

        // Then
        static::assertNotNull($this->bindings->findBySessionIdentifier($issued->sessionIdentifier));
    }

    private function handler(): RegistrationHandler
    {
        $verifier = new DeviceProofVerifier(new AlgorithmProvider([new ES256()], ['ES256']));
        $configFactory = new SessionConfigFactory('/dbsc/refresh', [
            'name' => 'dbsc_session',
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
            'lifetime' => 600,
        ]);

        return new RegistrationHandler(
            $verifier,
            $this->challengeManager,
            $this->bindings,
            $configFactory,
            new TokenGenerator(),
            $this->clock,
        );
    }

    /**
     * Signs a registration proof, embedding the key's public part in the `jwk` protected header.
     *
     * @param array<string, mixed> $payload
     */
    private function sign(JWK $key, array $payload): string
    {
        $jwk = $key->toPublic()
            ->all();

        $builder = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $jws = $builder->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'ES256',
                'typ' => 'dbsc+jwt',
                'jwk' => $jwk,
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
