<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Session;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Jwt\DeviceProof;
use SpomkyLabs\DbscBundle\Session\SessionBinding;

/**
 * @internal
 */
final class SessionBindingTest extends TestCase
{
    #[Test]
    public function itIsDeviceBoundWhenItHoldsARealKey(): void
    {
        // Given
        $binding = new SessionBinding('sid', [
            'kty' => 'EC',
            'crv' => 'P-256',
        ]);

        // Then
        static::assertTrue($binding->isDeviceBound());
        static::assertTrue($binding->withCookieToken('tok')->isDeviceBound());
    }

    #[Test]
    public function itIsNotDeviceBoundWhenRegisteredWithNone(): void
    {
        // Given
        $binding = new SessionBinding('sid', DeviceProof::UNBOUND_KEY);

        // Then
        static::assertFalse($binding->isDeviceBound());
        static::assertFalse($binding->withCookieToken('tok')->isDeviceBound());
    }
}
