<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Session\SessionBinding;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Drives the full refresh handshake with a real device key: the unsigned request gets a 403
 * challenge, the signed proof gets a 200 with a rotated cookie.
 *
 * @internal
 */
final class RefreshRoundTripTest extends WebTestCase
{
    #[Test]
    public function itRefreshesAndPreprovisionsTheNextChallengeWhenEnabled(): void
    {
        // Given a registered device key on the "secured" firewall, which pre-provisions challenges
        $client = self::createClient();
        $client->disableReboot();
        $key = $this->seedBinding('secured', 'sid-1', 'tok-1');

        // When the browser runs the handshake
        $challenge = $this->requestChallenge($client, '/dbsc/secured/refresh', 'sid-1');
        $this->postProof($client, '/dbsc/secured/refresh', 'sid-1', $this->sign($key, $challenge, 'http://localhost/dbsc/secured/refresh'));

        // Then the refresh succeeds and the response already carries the next challenge for this session
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertNotSame('tok-1', $response->headers->getCookies()[0]->getValue());
        $next = (string) $response->headers->get(SecureSessionHeaders::CHALLENGE);
        static::assertStringEndsWith(';id="sid-1"', $next);
        static::assertNotSame($challenge, explode('"', $next)[1]);
    }

    #[Test]
    public function itRefreshesWithoutPreprovisioningByDefault(): void
    {
        // Given a registered device key on the "login" firewall, which keeps the default
        $client = self::createClient();
        $client->disableReboot();
        $key = $this->seedBinding('login', 'sid-2', 'tok-2');

        // When the browser runs the handshake
        $challenge = $this->requestChallenge($client, '/dbsc/login/refresh', 'sid-2');
        $this->postProof($client, '/dbsc/login/refresh', 'sid-2', $this->sign($key, $challenge, 'http://localhost/dbsc/login/refresh'));

        // Then the refresh succeeds without a pre-provisioned challenge
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has(SecureSessionHeaders::CHALLENGE));
    }

    private function seedBinding(string $firewall, string $sessionId, string $cookieToken): JWK
    {
        $key = JWKFactory::createECKey('P-256');
        /** @var SessionBindingRepository $repository */
        $repository = static::getContainer()->get('dbsc.binding_repository.' . $firewall);
        $repository->save(new SessionBinding($sessionId, $key->toPublic()->all(), 'alice', 1_000, $cookieToken));

        return $key;
    }

    private function requestChallenge(KernelBrowser $client, string $path, string $sessionId): string
    {
        $client->request('POST', $path, [], [], [
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::SESSION_ID)) => $sessionId,
        ]);
        static::assertSame(Response::HTTP_FORBIDDEN, $client->getResponse()->getStatusCode());

        return explode('"', (string) $client->getResponse()->headers->get(SecureSessionHeaders::CHALLENGE))[1];
    }

    private function postProof(KernelBrowser $client, string $path, string $sessionId, string $proof): void
    {
        $client->request('POST', $path, [], [], [
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::SESSION_ID)) => $sessionId,
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::RESPONSE)) => $proof,
        ]);
    }

    private function sign(JWK $key, string $challenge, string $audience): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new ES256()])))->create()
            ->withPayload(json_encode([
                'jti' => $challenge,
                'aud' => $audience,
            ], JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'ES256',
                'typ' => 'dbsc+jwt',
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
