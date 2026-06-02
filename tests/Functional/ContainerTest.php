<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifierInterface;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandlerInterface;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandlerInterface;
use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * @internal
 */
final class ContainerTest extends KernelTestCase
{
    #[Test]
    public function theContainerCompilesAndWiresTheProtocolServices(): void
    {
        // Given a booted kernel
        self::bootKernel();
        $container = static::getContainer();

        // Then the public-facing protocol services are wired through their interfaces
        static::assertInstanceOf(
            DeviceProofVerifierInterface::class,
            $container->get(DeviceProofVerifierInterface::class)
        );
        static::assertInstanceOf(
            ChallengeManagerInterface::class,
            $container->get(ChallengeManagerInterface::class)
        );
        static::assertInstanceOf(
            RegistrationHandlerInterface::class,
            $container->get(RegistrationHandlerInterface::class)
        );
        static::assertInstanceOf(RefreshHandlerInterface::class, $container->get(RefreshHandlerInterface::class));
    }

    #[Test]
    public function itRegistersTheRegistrationAndRefreshRoutes(): void
    {
        // Given
        self::bootKernel();
        /** @var Router $router */
        $router = static::getContainer()->get('router');
        $routes = $router->getRouteCollection();

        // Then
        static::assertNotNull($routes->get('dbsc_register'));
        static::assertNotNull($routes->get('dbsc_refresh'));
        static::assertSame('/dbsc/register', $routes->get('dbsc_register')?->getPath());
        static::assertSame('/dbsc/refresh', $routes->get('dbsc_refresh')?->getPath());
    }
}
