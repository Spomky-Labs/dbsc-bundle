<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * @internal
 */
final class RegistrationFlowTest extends WebTestCase
{
    #[Test]
    public function itEmitsTheRegistrationHeaderWhenTheCheckboxIsTicked(): void
    {
        // Given a login that opts in through the checkbox parameter
        $client = self::createClient();

        // When the user logs in with the device-bound checkbox ticked
        $client->request('POST', '/test-login', [
            '_device_bound_session' => '1',
        ]);

        // Then the response asks a supporting browser to register a device-bound key
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertTrue($response->headers->has(SecureSessionHeaders::REGISTRATION));
        static::assertStringContainsString(
            'challenge=',
            (string) $response->headers->get(SecureSessionHeaders::REGISTRATION)
        );
    }

    #[Test]
    public function itDoesNotEmitWhenTheCheckboxIsAbsent(): void
    {
        // Given a login without the device-bound checkbox
        $client = self::createClient();

        // When the user logs in
        $client->request('POST', '/test-login');

        // Then no registration header is emitted
        $response = $client->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has(SecureSessionHeaders::REGISTRATION));
    }
}
