<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class RefreshEndpointTest extends WebTestCase
{
    #[Test]
    public function itAnswersWithAChallengeWhenNoProofIsProvided(): void
    {
        // Given a refresh request carrying only the session id
        $client = self::createClient();

        // When
        $client->request('POST', '/dbsc/login/refresh', [], [], [
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::SESSION_ID)) => 'session-1',
        ]);

        // Then the server challenges the device with a 403 carrying the session id
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        static::assertTrue($response->headers->has(SecureSessionHeaders::CHALLENGE));
        $challenge = (string) $response->headers->get(SecureSessionHeaders::CHALLENGE);
        static::assertNotSame('', $challenge);
        static::assertStringContainsString('id="session-1"', $challenge);
    }

    #[Test]
    public function itRejectsARefreshWithoutASessionId(): void
    {
        // Given
        $client = self::createClient();

        // When
        $client->request('POST', '/dbsc/login/refresh');

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $client->getResponse()->getStatusCode());
    }

    #[Test]
    public function itChallengesAnUnknownSessionRatherThanLeakingItsExistence(): void
    {
        // Given a proof for a session that was never registered
        $client = self::createClient();

        // When
        $this->postProof($client, 'unknown-session', 'not-a-valid-jws');

        // Then the refresh is not granted (re-challenge)
        static::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    private function postProof(KernelBrowser $client, string $sessionId, string $proof): void
    {
        $client->request('POST', '/dbsc/login/refresh', [], [], [
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::SESSION_ID)) => $sessionId,
            'HTTP_' . str_replace('-', '_', strtoupper(SecureSessionHeaders::RESPONSE)) => $proof,
        ]);
    }
}
