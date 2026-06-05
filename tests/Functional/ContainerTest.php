<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
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
    public function theContainerCompilesAndWiresThePerFirewallProtocolServices(): void
    {
        // Given a booted kernel with DBSC enabled on the "login" and "secured" firewalls
        self::bootKernel();
        $container = static::getContainer();

        // Then each firewall has its own handler graph
        static::assertInstanceOf(
            RegistrationHandlerInterface::class,
            $container->get('dbsc.registration_handler.login')
        );
        static::assertInstanceOf(RefreshHandlerInterface::class, $container->get('dbsc.refresh_handler.login'));
        static::assertInstanceOf(
            RegistrationHandlerInterface::class,
            $container->get('dbsc.registration_handler.secured')
        );
        static::assertInstanceOf(RefreshHandlerInterface::class, $container->get('dbsc.refresh_handler.secured'));
    }

    #[Test]
    public function itRegistersOneRoutePairPerFirewall(): void
    {
        // Given
        self::bootKernel();
        /** @var Router $router */
        $router = static::getContainer()->get('router');
        $routes = $router->getRouteCollection();

        // Then the routes are derived from the firewall names
        static::assertSame('/dbsc/login/register', $routes->get('dbsc_register_login')?->getPath());
        static::assertSame('/dbsc/login/refresh', $routes->get('dbsc_refresh_login')?->getPath());
        static::assertSame('/dbsc/secured/register', $routes->get('dbsc_register_secured')?->getPath());
        static::assertSame('/dbsc/secured/refresh', $routes->get('dbsc_refresh_secured')?->getPath());
    }
}
