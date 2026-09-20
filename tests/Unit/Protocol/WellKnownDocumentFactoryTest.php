<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Protocol;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Protocol\WellKnownDocumentFactory;

/**
 * @internal
 */
final class WellKnownDocumentFactoryTest extends TestCase
{
    #[Test]
    public function itBuildsARelyingPartyDocument(): void
    {
        // When a site names its session provider
        $document = WellKnownDocumentFactory::create('https://idp.example', [], []);

        // Then only provider_origin is served
        static::assertSame([
            'provider_origin' => 'https://idp.example',
        ], $document);
    }

    #[Test]
    public function itBuildsAProviderDocument(): void
    {
        // When a site lists relying and registering origins
        $document = WellKnownDocumentFactory::create(null, ['https://rp.example'], ['https://reg.example']);

        // Then
        static::assertSame([
            'relying_origins' => ['https://rp.example'],
            'registering_origins' => ['https://reg.example'],
        ], $document);
    }

    #[Test]
    public function itOmitsRegisteringOriginsWhenEmpty(): void
    {
        // When
        $document = WellKnownDocumentFactory::create(null, ['https://rp.example'], []);

        // Then
        static::assertSame([
            'relying_origins' => ['https://rp.example'],
        ], $document);
    }

    #[Test]
    public function itBuildsNothingWhenFederationIsNotConfigured(): void
    {
        // Then
        static::assertNull(WellKnownDocumentFactory::create(null, [], []));
    }

    #[Test]
    public function itRefusesASiteThatIsBothProviderAndRelyingParty(): void
    {
        // Then the spec forbids provider_origin and relying_origins in the same document
        $this->expectException(InvalidArgumentException::class);

        // When
        WellKnownDocumentFactory::create('https://idp.example', ['https://rp.example'], []);
    }
}
