<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Http;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactory;

/**
 * @internal
 */
final class BoundCookieFactoryTest extends TestCase
{
    #[Test]
    public function itCreatesAShortLivedBoundCookie(): void
    {
        // Given
        $factory = $this->createFactory();

        // When
        $cookie = $factory->create('grant-value', 1_000);

        // Then
        static::assertSame('__Host-Http-dbsc_session', $cookie->getName());
        static::assertSame('grant-value', $cookie->getValue());
        static::assertSame(1_600, $cookie->getExpiresTime());
        static::assertTrue($cookie->isSecure());
        static::assertTrue($cookie->isHttpOnly());
        static::assertSame('lax', $cookie->getSameSite());
    }

    #[Test]
    public function itClearsTheCookie(): void
    {
        // Given
        $factory = $this->createFactory();

        // When
        $cookie = $factory->clear();

        // Then
        static::assertSame('__Host-Http-dbsc_session', $cookie->getName());
        static::assertTrue($cookie->isCleared() || $cookie->getValue() === '');
    }

    private function createFactory(): BoundCookieFactory
    {
        return new BoundCookieFactory([
            'name' => '__Host-Http-dbsc_session',
            'lifetime' => 600,
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ]);
    }
}
