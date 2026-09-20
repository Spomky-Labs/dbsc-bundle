<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Protocol;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Protocol\SessionProvider;

/**
 * @internal
 */
final class SessionProviderTest extends TestCase
{
    #[Test]
    public function itRequiresAllThreeValues(): void
    {
        // Then the spec ignores a registration missing any of the provider parameters
        $this->expectException(InvalidArgumentException::class);

        // When
        new SessionProvider('https://idp.example', '', 'thumb');
    }

    #[Test]
    public function itHoldsTheProviderCoordinates(): void
    {
        // When
        $provider = new SessionProvider('https://idp.example', 'sid', 'thumb');

        // Then
        static::assertSame('https://idp.example', $provider->url);
        static::assertSame('sid', $provider->sessionId);
        static::assertSame('thumb', $provider->keyThumbprint);
    }
}
