<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Routing;

use SpomkyLabs\DbscBundle\Controller\WellKnownController;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Emits the DBSC registration and refresh routes, one pair per firewall that enables
 * `device_bound_session`. Each route targets that firewall's dedicated controller service,
 * so the incoming request alone determines which firewall configuration applies, with no runtime
 * firewall resolution is needed.
 *
 * The firewalls map is populated by {@see \SpomkyLabs\DbscBundle\Security\Factory\DeviceBoundSessionFactory}
 * into the `dbsc.firewalls` container parameter. Activated through the `dbsc` loader type from
 * the bundle's config/routes.php.
 *
 * When federation is configured it also serves `/.well-known/device-bound-sessions`, the
 * per-origin document browsers check before sharing a device key between sites.
 */
final class DbscRouteLoader extends Loader
{
    public const WELL_KNOWN_PATH = '/.well-known/device-bound-sessions';

    /**
     * @param array<string, array{register: string, refresh: string, registration_controller: string, refresh_controller: string}> $firewalls
     * @param bool                                                                                                                  $wellKnown whether the well-known document is configured
     */
    public function __construct(
        private readonly array $firewalls,
        private readonly bool $wellKnown = false,
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

        if ($this->wellKnown) {
            $collection->add(
                'dbsc_well_known',
                new Route(self::WELL_KNOWN_PATH, [
                    '_controller' => WellKnownController::class,
                ], methods: ['GET']),
            );
        }

        return $collection;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'dbsc';
    }
}
