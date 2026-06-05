<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use SpomkyLabs\DbscBundle\Tests\LoginTestAuthenticator;
use SpomkyLabs\DbscBundle\Tests\SecuredController;

return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
    ;
    $services->set(SecuredController::class)
        ->tag('controller.service_arguments');
    $services->set(LoginTestAuthenticator::class);

    $container->extension('framework', [
        'test' => true,
        'secret' => 'test',
        'http_method_override' => true,
        'handle_all_throwables' => true,
        'session' => [
            'storage_factory_id' => 'session.storage.factory.mock_file',
            'cookie_secure' => 'auto',
            'cookie_samesite' => 'lax',
            'handler_id' => 'session.handler.native_file',
        ],
        'router' => [
            'utf8' => true,
            'resource' => '%kernel.project_dir%/tests/routes.php',
        ],
        'default_locale' => 'en',
        'php_errors' => [
            'log' => true,
        ],
    ]);

    $container->extension('security', [
        'providers' => [
            'in_memory' => [
                'memory' => [
                    'users' => [
                        'alice' => [
                            'password' => 'test',
                            'roles' => ['ROLE_USER'],
                        ],
                    ],
                ],
            ],
        ],
        'firewalls' => [
            'login' => [
                'pattern' => '^/test-login',
                'stateless' => true,
                'provider' => 'in_memory',
                'custom_authenticators' => [LoginTestAuthenticator::class],
                'device_bound_session' => [
                    'checkbox' => '_device_bound_session',
                ],
            ],
            'secured' => [
                'pattern' => '^/secured',
                'stateless' => true,
                'provider' => 'in_memory',
                'device_bound_session' => [
                    'authenticate' => true,
                ],
            ],
            'main' => [
                'lazy' => true,
                'provider' => 'in_memory',
            ],
        ],
        'access_control' => [
            [
                'path' => '^/secured/fully',
                'roles' => 'IS_AUTHENTICATED_FULLY',
            ],
            [
                'path' => '^/secured',
                'roles' => 'ROLE_USER',
            ],
        ],
    ]);
};
