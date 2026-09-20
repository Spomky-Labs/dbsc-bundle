<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Controller;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Controller\RefreshController;
use SpomkyLabs\DbscBundle\Exception\SessionExpiredException;
use SpomkyLabs\DbscBundle\Exception\UnknownSessionException;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactory;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\ChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Protocol\ChallengePreprovisionerInterface;
use SpomkyLabs\DbscBundle\Protocol\IssuedSession;
use SpomkyLabs\DbscBundle\Protocol\NullChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandlerInterface;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactory;
use SpomkyLabs\DbscBundle\Tests\FixedClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class RefreshControllerTest extends TestCase
{
    #[Test]
    public function itGracefullyTerminatesAnExpiredSession(): void
    {
        // Given a handler that reports the session lifetime has elapsed
        $handler = static::createStub(RefreshHandlerInterface::class);
        $handler->method('refresh')
            ->willThrowException(SessionExpiredException::forIdentifier('session-1'));

        // When a proof is presented for it
        $response = $this->controller($handler)
            ->__invoke($this->proofRequest('session-1'));

        // Then the browser is told to stop with continue: false and the cookie is cleared
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('{"continue":false}', (string) $response->getContent());
        $cookies = $response->headers->getCookies();
        static::assertNotSame([], $cookies);
        static::assertSame('', $cookies[0]->getValue());
    }

    #[Test]
    public function itTerminatesAnUnknownSessionWithA401(): void
    {
        // Given a handler that does not know the session
        $handler = static::createStub(RefreshHandlerInterface::class);
        $handler->method('refresh')
            ->willThrowException(UnknownSessionException::forIdentifier('session-1'));

        // When
        $response = $this->controller($handler)
            ->__invoke($this->proofRequest('session-1'));

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    #[Test]
    public function itPreprovisionsTheNextChallengeOnASuccessfulRefresh(): void
    {
        // Given a handler that grants the refresh and a firewall with pre-provisioning enabled
        $handler = static::createStub(RefreshHandlerInterface::class);
        $handler->method('refresh')
            ->willReturn(new IssuedSession('session-1', 'new-token', [
                'session_identifier' => 'session-1',
            ]));
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $manager = new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300);

        // When
        $response = $this->controller($handler, new ChallengePreprovisioner($manager, 600, 300))
            ->__invoke($this->proofRequest('session-1'));

        // Then the 200 carries the rotated cookie and the next challenge bound to the session
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('new-token', $response->headers->getCookies()[0]->getValue());
        static::assertStringEndsWith(';id="session-1"', (string) $response->headers->get(SecureSessionHeaders::CHALLENGE));
    }

    #[Test]
    public function itDoesNotPreprovisionByDefault(): void
    {
        // Given a handler that grants the refresh on a firewall without pre-provisioning
        $handler = static::createStub(RefreshHandlerInterface::class);
        $handler->method('refresh')
            ->willReturn(new IssuedSession('session-1', 'new-token', []));

        // When
        $response = $this->controller($handler)
            ->__invoke($this->proofRequest('session-1'));

        // Then
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has(SecureSessionHeaders::CHALLENGE));
    }

    private function controller(
        RefreshHandlerInterface $handler,
        ChallengePreprovisionerInterface $preprovisioner = new NullChallengePreprovisioner(),
    ): RefreshController {
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $cookie = [
            'name' => 'dbsc_session',
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
            'lifetime' => 600,
        ];

        return new RefreshController(
            $handler,
            new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300),
            new BoundCookieFactory($cookie),
            $clock,
            new SessionConfigFactory('/dbsc/refresh', $cookie),
            preprovisioner: $preprovisioner,
        );
    }

    private function proofRequest(string $sessionId): Request
    {
        $request = Request::create('/dbsc/refresh', 'POST');
        $request->headers->set(SecureSessionHeaders::SESSION_ID, $sessionId);
        $request->headers->set(SecureSessionHeaders::RESPONSE, 'a-proof');

        return $request;
    }
}
