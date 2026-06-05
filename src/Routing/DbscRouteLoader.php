<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Routing;

use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Emits the DBSC registration and refresh routes, one pair per firewall that enables
 * `device_bound_session`. Each route targets that firewall's dedicated controller service,
 * so the incoming request alone determines which firewall configuration applies — no runtime
 * firewall resolution is needed.
 *
 * The firewalls map is populated by {@see \SpomkyLabs\DbscBundle\Security\Factory\DeviceBoundSessionFactory}
 * into the `dbsc.firewalls` container parameter. Activated through the `dbsc` loader type from
 * the bundle's config/routes.php.
 */
final class DbscRouteLoader extends Loader
{
    /**
     * @param array<string, array{register: string, refresh: string, registration_controller: string, refresh_controller: string}> $firewalls
     */
    public function __construct(
        private readonly array $firewalls,
        ?string $env = null,
    ) {
        parent::__construct($env);
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        $collection = new RouteCollection();

        foreach ($this->firewalls as $firewall => $config) {
            $collection->add(
                'dbsc_register_' . $firewall,
                new Route($config['register'], [
                    '_controller' => $config['registration_controller'],
                ], methods: ['POST']),
            );
            $collection->add(
                'dbsc_refresh_' . $firewall,
                new Route($config['refresh'], [
                    '_controller' => $config['refresh_controller'],
                ], methods: ['POST']),
            );
        }

        return $collection;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'dbsc';
    }
}
