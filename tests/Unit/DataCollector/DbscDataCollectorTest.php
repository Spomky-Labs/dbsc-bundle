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
        static::assertSame(['ES256', 'RS256'], $collector->getData()['firewalls']['main']['algorithms']);
        static::assertTrue($collector->getData()['firewalls']['main']['cookie_present']);
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
    }

    private function collector(): DbscDataCollector
    {
        return new DbscDataCollector(
            [
                'main' => [
                    'register' => '/dbsc/main/register',
                    'refresh' => '/dbsc/main/refresh',
                    'cookie_name' => '__Host-Http-dbsc_session',
                    'algorithms' => ['ES256', 'RS256'],
                    'challenge_ttl' => 300,
                    'authenticate' => false,
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
