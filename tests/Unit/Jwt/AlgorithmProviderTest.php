<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Unit\Jwt;

use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;

/**
 * @internal
 */
final class AlgorithmProviderTest extends TestCase
{
    #[Test]
    public function itBuildsAManagerLimitedToTheAllowedAlgorithms(): void
    {
        // Given every algorithm is available as a tagged service
        $provider = new AlgorithmProvider([new ES256(), new RS256()], ['ES256']);

        // When
        $manager = $provider->getManager();

        // Then only the allowed one is selected
        static::assertTrue($manager->has('ES256'));
        static::assertFalse($manager->has('RS256'));
        static::assertSame(['ES256'], $provider->getAllowedNames());
    }

    #[Test]
    public function itRejectsAnAllowedAlgorithmThatIsNotAvailable(): void
    {
        // Given an allow-list referencing an unavailable algorithm
        $provider = new AlgorithmProvider([new ES256()], ['RS256']);

        // Then
        $this->expectException(InvalidProofException::class);

        // When
        $provider->getManager();
    }
}
