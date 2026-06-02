<?php

declare(strict_types=1);

use SpomkyLabs\DbscBundle\Controller\RefreshController;
use SpomkyLabs\DbscBundle\Controller\RegistrationController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    $routes->add('dbsc_register', '%dbsc.registration.path%')
        ->controller(RegistrationController::class)
        ->methods(['POST']);

    $routes->add('dbsc_refresh', '%dbsc.refresh.path%')
        ->controller(RefreshController::class)
        ->methods(['POST']);
};
