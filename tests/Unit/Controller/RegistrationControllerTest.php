<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Controller;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Controller\RegistrationController;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactory;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\ChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Protocol\ChallengePreprovisionerInterface;
use SpomkyLabs\DbscBundle\Protocol\IssuedSession;
use SpomkyLabs\DbscBundle\Protocol\NullChallengePreprovisioner;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandlerInterface;
use SpomkyLabs\DbscBundle\Tests\FixedClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * @internal
 */
final class RegistrationControllerTest extends TestCase
{
    #[Test]
    public function itIssuesTheBoundCookieAndTheSessionConfig(): void
    {
        // Given a handler that accepts the registration proof
        $handler = static::createStub(RegistrationHandlerInterface::class);
        $handler->method('register')
            ->willReturn(new IssuedSession('session-1', 'first-token', [
                'session_identifier' => 'session-1',
            ]));

        // When
        $response = $this->controller($handler)
            ->__invoke($this->proofRequest());

        // Then
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('{"session_identifier":"session-1"}', (string) $response->getContent());
        static::assertSame('first-token', $response->headers->getCookies()[0]->getValue());
        static::assertFalse($response->headers->has(SecureSessionHeaders::CHALLENGE));
    }

    #[Test]
    public function itPreprovisionsTheFirstRefreshChallengeWhenEnabled(): void
    {
        // Given a firewall with pre-provisioning enabled
        $handler = static::createStub(RegistrationHandlerInterface::class);
        $handler->method('register')
            ->willReturn(new IssuedSession('session-1', 'first-token', []));
        $clock = new FixedClock(new DateTimeImmutable('2026-01-01T00:00:00+00:00'));
        $manager = new ChallengeManager(new InMemoryChallengeStore($clock), $clock, 300);

        // When
        $response = $this->controller($handler, new ChallengePreprovisioner($manager, 600, 300))
            ->__invoke($this->proofRequest());

        // Then the registration response already carries the challenge for the first refresh
        static::assertStringEndsWith(';id="session-1"', (string) $response->headers->get(SecureSessionHeaders::CHALLENGE));
    }

    #[Test]
    public function itRejectsAnInvalidProofWithA400(): void
    {
        // Given
        $handler = static::createStub(RegistrationHandlerInterface::class);
        $handler->method('register')
            ->willThrowException(InvalidProofException::badSignature());

        // When
        $response = $this->controller($handler)
            ->__invoke($this->proofRequest());

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame([], $response->headers->getCookies());
    }

    private function controller(
        RegistrationHandlerInterface $handler,
        ChallengePreprovisionerInterface $preprovisioner = new NullChallengePreprovisioner(),
    ): RegistrationController {
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

        return new RegistrationController(
            $handler,
            new BoundCookieFactory($cookie),
            new TokenStorage(),
            $clock,
            preprovisioner: $preprovisioner,
        );
    }

    private function proofRequest(): Request
    {
        $request = Request::create('/dbsc/register', 'POST');
        $request->headers->set(SecureSessionHeaders::RESPONSE, 'a-proof');

        return $request;
    }
}
