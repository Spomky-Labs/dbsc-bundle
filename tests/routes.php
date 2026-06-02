<?php

declare(strict_types=1);

use SpomkyLabs\DbscBundle\Tests\SecuredController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    $routes->import(__DIR__ . '/../config/routes.php');
    $routes->import(SecuredController::class, 'attribute');
};
