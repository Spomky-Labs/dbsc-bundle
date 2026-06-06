<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\DataCollector;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeStore;
use SpomkyLabs\DbscBundle\DataCollector\DbscDataCollector;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class DbscDataCollectorTest extends TestCase
{
    #[Test]
    public function itCollectsTheRegistrationHeaderAndPerFirewallBoundCookie(): void
    {
        // Given a response carrying the registration header and a request with the bound cookie
        $collector = $this->collector();
        $request = new Request([], [], [], [
            '__Host-Http-dbsc_session' => 'tok-abcdef123',
        ]);
        $response = new Response();
        $response->headers->set(
            SecureSessionHeaders::REGISTRATION,
            '(ES256 RS256);challenge="chal-42";path="/dbsc/main/register"',
        );

        // When
        $collector->collect($request, $response);

        // Then
        static::assertTrue($collector->isRegistrationRequested());
        static::assertTrue($collector->isCookiePresent());
        static::assertSame('chal-42', $collector->getData()['challenge']);
        static::assertSame(['ES256', 'RS256'], $collector->getData()['registration']['algorithms']);
        static::assertSame('/dbsc/main/register', $collector->getData()['registration']['path']);
        static::assertSame(['ES256', 'RS256'], $collector->getData()['firewalls']['main']['algorithms']);
        static::assertTrue($collector->getData()['firewalls']['main']['cookie_present']);
        static::assertNull($collector->getEndpoint());
    }

    #[Test]
    public function itExposesTheFullPerFirewallConfiguration(): void
    {
        // Given a bare request on a fully configured firewall
        $collector = $this->collector();

        // When
        $collector->collect(new Request(), new Response());

        // Then
        $firewall = $collector->getData()['firewalls']['main'];
        static::assertFalse($firewall['always']);
        static::assertSame('_device_bound_session', $firewall['checkbox']);
        static::assertSame(300, $firewall['challenge_ttl']);
        static::assertNull($firewall['session_lifetime']);
        static::assertFalse($firewall['include_site']);
        static::assertSame(['/build'], $firewall['scope_exclude_paths']);
        static::assertSame(600, $firewall['cookie']['lifetime']);
        static::assertSame('lax', $firewall['cookie']['same_site']);
    }

    #[Test]
    public function itReportsAbsenceWhenNeitherHeaderNorCookieIsPresent(): void
    {
        // Given a bare request/response
        $collector = $this->collector();

        // When
        $collector->collect(new Request(), new Response());

        // Then
        static::assertFalse($collector->isRegistrationRequested());
        static::assertFalse($collector->isCookiePresent());
        static::assertNull($collector->getRegistrationHeader());
        static::assertNull($collector->getEndpoint());
    }

    #[Test]
    public function itCapturesASuccessfulRegistrationRequest(): void
    {
        // Given a request hitting the registration endpoint with a proof and a successful response
        $collector = $this->collector();
        $request = Request::create('/dbsc/main/register', 'POST');
        $request->headers->set(SecureSessionHeaders::RESPONSE, $this->jws([
            'alg' => 'ES256',
        ], [
            'sub' => 'session-1',
        ]));
        $response = new JsonResponse([
            'session_identifier' => 'session-1',
        ]);
        $response->headers->setCookie(Cookie::create('__Host-Http-dbsc_session', 'tok-new12345'));

        // When
        $collector->collect($request, $response);

        // Then
        $endpoint = $collector->getEndpoint();
        static::assertNotNull($endpoint);
        static::assertSame('register', $endpoint['type']);
        static::assertSame('main', $endpoint['firewall']);
        static::assertSame('registered', $endpoint['outcome']);
        static::assertTrue($endpoint['had_proof']);
        static::assertSame('ES256', $endpoint['proof_header']['alg']);
        static::assertSame('session-1', $endpoint['proof_payload']['sub']);
        static::assertTrue($endpoint['cookie_set']);
        static::assertFalse($endpoint['cookie_cleared']);
    }

    #[Test]
    public function itCapturesARefreshChallengeRequest(): void
    {
        // Given a proofless refresh request answered with a challenge
        $collector = $this->collector();
        $request = Request::create('/dbsc/main/refresh', 'POST');
        $request->headers->set(SecureSessionHeaders::SESSION_ID, 'session-1');
        $response = new JsonResponse(null, Response::HTTP_FORBIDDEN);
        $response->headers->set(SecureSessionHeaders::CHALLENGE, '"chal-99";id="session-1"');

        // When
        $collector->collect($request, $response);

        // Then
        $endpoint = $collector->getEndpoint();
        static::assertNotNull($endpoint);
        static::assertSame('refresh', $endpoint['type']);
        static::assertSame('challenge_request', $endpoint['phase']);
        static::assertSame('challenge_issued', $endpoint['outcome']);
        static::assertSame('session-1', $endpoint['session_id']);
        static::assertFalse($endpoint['had_proof']);
        static::assertSame('"chal-99";id="session-1"', $endpoint['challenge']);
    }

    #[Test]
    public function itCapturesARefreshThatTerminatesTheSession(): void
    {
        // Given a refresh proof answered with a terminating continue:false document
        $collector = $this->collector();
        $request = Request::create('/dbsc/main/refresh', 'POST');
        $request->headers->set(SecureSessionHeaders::SESSION_ID, 'session-1');
        $request->headers->set(SecureSessionHeaders::RESPONSE, $this->jws([
            'alg' => 'ES256',
        ], [
            'jti' => 'chal-99',
        ]));
        $response = new JsonResponse([
            'session_identifier' => 'session-1',
            'continue' => false,
        ]);
        $response->headers->setCookie(Cookie::create('__Host-Http-dbsc_session', '', 1));

        // When
        $collector->collect($request, $response);

        // Then
        $endpoint = $collector->getEndpoint();
        static::assertNotNull($endpoint);
        static::assertSame('proof_submission', $endpoint['phase']);
        static::assertSame('terminated', $endpoint['outcome']);
        static::assertTrue($endpoint['cookie_cleared']);
        static::assertFalse($endpoint['cookie_set']);
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    private function jws(array $header, array $payload): string
    {
        $encode = static fn (array $part): string => rtrim(
            strtr(base64_encode((string) json_encode($part)), '+/', '-_'),
            '='
        );

        return $encode($header) . '.' . $encode($payload) . '.signature';
    }

    private function collector(): DbscDataCollector
    {
        return new DbscDataCollector(
            [
                'main' => [
                    'register' => '/dbsc/main/register',
                    'refresh' => '/dbsc/main/refresh',
                    'cookie_name' => '__Host-Http-dbsc_session',
                    'cookie' => [
                        'name' => '__Host-Http-dbsc_session',
                        'lifetime' => 600,
                        'path' => '/',
                        'domain' => null,
                        'secure' => true,
                        'http_only' => true,
                        'same_site' => 'lax',
                    ],
                    'algorithms' => ['ES256', 'RS256'],
                    'challenge_ttl' => 300,
                    'session_lifetime' => null,
                    'authenticate' => false,
                    'always' => false,
                    'checkbox' => '_device_bound_session',
                    'include_site' => false,
                    'scope_exclude_paths' => ['/build'],
                    'allowed_refresh_initiators' => [],
                    'binding_repository_service' => null,
                    'challenge_store_service' => null,
                ],
            ],
            new ServiceLocator([
                'main' => fn (): SessionBindingRepository => static::createStub(SessionBindingRepository::class),
            ]),
            new ServiceLocator([
                'main' => fn (): ChallengeStore => static::createStub(ChallengeStore::class),
            ]),
        );
    }
}
