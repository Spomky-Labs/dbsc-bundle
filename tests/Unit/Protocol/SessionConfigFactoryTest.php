<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Protocol;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactory;

/**
 * @internal
 */
final class SessionConfigFactoryTest extends TestCase
{
    #[Test]
    public function itBuildsTheSessionConfigDocument(): void
    {
        // Given a factory excluding the static asset paths from the scope
        $factory = new SessionConfigFactory('/dbsc/refresh', [
            'name' => '__Host-Http-dbsc_session',
            'lifetime' => 600,
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ], ['/assets', '/build']);

        // When
        $config = $factory->create('session-1', 'https://example.com');

        // Then
        static::assertSame('session-1', $config['session_identifier']);
        static::assertSame('/dbsc/refresh', $config['refresh_url']);
        static::assertSame('https://example.com', $config['scope']['origin']);
        static::assertFalse($config['scope']['include_site']);
        static::assertSame([
            [
                'type' => 'include',
                'domain' => 'example.com',
                'path' => '/',
            ],
            [
                'type' => 'exclude',
                'domain' => 'example.com',
                'path' => '/assets',
            ],
            [
                'type' => 'exclude',
                'domain' => 'example.com',
                'path' => '/build',
            ],
        ], $config['scope']['scope_specification']);
        static::assertSame('__Host-Http-dbsc_session', $config['credentials'][0]['name']);
        static::assertStringContainsString('Secure', (string) $config['credentials'][0]['attributes']);
        static::assertStringContainsString('SameSite=Lax', (string) $config['credentials'][0]['attributes']);
    }

    #[Test]
    public function itEmitsASiteScopedSessionWhenIncludeSiteIsOn(): void
    {
        // Given a factory configured to emit a site-scoped session
        $factory = new SessionConfigFactory('/dbsc/refresh', [
            'name' => 'dbsc_session',
            'lifetime' => 600,
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ], [], true);

        // When
        $config = $factory->create('session-1', 'https://example.com');

        // Then
        static::assertTrue($config['scope']['include_site']);
    }

    #[Test]
    public function itOmitsAllowedRefreshInitiatorsWhenEmpty(): void
    {
        // Given a factory with no allowed refresh initiators
        $factory = $this->factory([]);

        // When
        $config = $factory->create('session-1', 'https://example.com');

        // Then the optional key is not emitted
        static::assertArrayNotHasKey('allowed_refresh_initiators', $config);
    }

    #[Test]
    public function itEmitsAllowedRefreshInitiatorsWhenConfigured(): void
    {
        // Given a factory with allowed refresh initiators
        $factory = $this->factory(['https://app.example.com']);

        // When
        $config = $factory->create('session-1', 'https://example.com');

        // Then
        static::assertSame(['https://app.example.com'], $config['allowed_refresh_initiators']);
    }

    /**
     * @param list<string> $allowedRefreshInitiators
     */
    private function factory(array $allowedRefreshInitiators): SessionConfigFactory
    {
        return new SessionConfigFactory('/dbsc/refresh', [
            'name' => 'dbsc_session',
            'lifetime' => 600,
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ], [], false, $allowedRefreshInitiators);
    }
}
