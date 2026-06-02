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
        // Given
        $factory = new SessionConfigFactory('/dbsc/refresh', [
            'name' => '__Host-dbsc_session',
            'lifetime' => 600,
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ]);

        // When
        $config = $factory->create('session-1', 'https://example.com');

        // Then
        static::assertSame('session-1', $config['session_identifier']);
        static::assertSame('/dbsc/refresh', $config['refresh_url']);
        static::assertSame('https://example.com', $config['scope']['origin']);
        static::assertTrue($config['scope']['include_site']);
        static::assertSame('__Host-dbsc_session', $config['credentials'][0]['name']);
        static::assertStringContainsString('Secure', (string) $config['credentials'][0]['attributes']);
        static::assertStringContainsString('SameSite=Lax', (string) $config['credentials'][0]['attributes']);
    }
}
