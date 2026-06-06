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

    private function controller(RefreshHandlerInterface $handler): RefreshController
    {
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
