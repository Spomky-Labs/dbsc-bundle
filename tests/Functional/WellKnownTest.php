<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class WellKnownTest extends WebTestCase
{
    #[Test]
    public function itServesTheSessionProviderDocument(): void
    {
        // Given a kernel configured as a session provider for https://rp.example
        $client = self::createClient();

        // When a browser fetches the well-known document
        $client->request('GET', '/.well-known/device-bound-sessions');

        // Then it gets the JSON the spec expects, without provider_origin
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertSame('{"relying_origins":["https://rp.example"]}', (string) $response->getContent());
    }
}
