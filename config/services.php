<?php

declare(strict_types=1);

use Jose\Component\Core\Algorithm;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Psr\Clock\ClockInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeStore;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Controller\RefreshController;
use SpomkyLabs\DbscBundle\Controller\RegistrationController;
use SpomkyLabs\DbscBundle\DataCollector\DbscDataCollector;
use SpomkyLabs\DbscBundle\EventListener\DeviceBoundSessionConditionsListener;
use SpomkyLabs\DbscBundle\EventListener\RegistrationHeaderListener;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactory;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactoryInterface;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProviderInterface;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifier;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifierInterface;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandler;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandlerInterface;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandler;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandlerInterface;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactory;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactoryInterface;
use SpomkyLabs\DbscBundle\Protocol\TokenGenerator;
use SpomkyLabs\DbscBundle\Protocol\TokenGeneratorInterface;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionAuthenticator;
use SpomkyLabs\DbscBundle\Session\InMemorySessionBindingRepository;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use function Symfony\Component\DependencyInjection\Loader\Configurator\abstract_arg;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure()
        ->bind(ClockInterface::class, service('clock'));

    $services->instanceof(Algorithm::class)
        ->tag('dbsc.jose_algorithm');

    $services->set(ES256::class);
    $services->set(ES384::class);
    $services->set(ES512::class);
    $services->set(RS256::class);
    $services->set(RS384::class);
    $services->set(RS512::class);
    $services->set(PS256::class);
    $services->set(PS384::class);
    $services->set(PS512::class);

    $services->set(AlgorithmProvider::class)
        ->args([tagged_iterator('dbsc.jose_algorithm'), '%dbsc.algorithms%']);
    $services->alias(AlgorithmProviderInterface::class, AlgorithmProvider::class);

    $services->set(DeviceProofVerifier::class);
    $services->alias(DeviceProofVerifierInterface::class, DeviceProofVerifier::class);

    $services->set(InMemoryChallengeStore::class);
    $services->alias(ChallengeStore::class, InMemoryChallengeStore::class);
    $services->set(ChallengeManager::class)
        ->arg('$ttl', '%dbsc.challenge.ttl%');
    $services->alias(ChallengeManagerInterface::class, ChallengeManager::class);

    $services->set(InMemorySessionBindingRepository::class);
    $services->alias(SessionBindingRepository::class, InMemorySessionBindingRepository::class);

    $services->set(TokenGenerator::class);
    $services->alias(TokenGeneratorInterface::class, TokenGenerator::class);

    $services->set(BoundCookieFactory::class)
        ->arg('$config', '%dbsc.cookie%');
    $services->alias(BoundCookieFactoryInterface::class, BoundCookieFactory::class);

    $services->set(SessionConfigFactory::class)
        ->args(['%dbsc.refresh.path%', '%dbsc.cookie%']);
    $services->alias(SessionConfigFactoryInterface::class, SessionConfigFactory::class);

    $services->set(RegistrationHandler::class);
    $services->alias(RegistrationHandlerInterface::class, RegistrationHandler::class);

    $services->set(RefreshHandler::class);
    $services->alias(RefreshHandlerInterface::class, RefreshHandler::class);

    $services->set('dbsc.security.conditions_listener', DeviceBoundSessionConditionsListener::class)
        ->abstract()
        ->args([
            abstract_arg('always, set by the security factory'),
            abstract_arg('checkbox parameter, set by the security factory'),
        ]);

    $services->set('dbsc.security.header_listener', RegistrationHeaderListener::class)
        ->abstract()
        ->args([
            service(ChallengeManagerInterface::class),
            service(AlgorithmProviderInterface::class),
            '%dbsc.registration.path%',
        ]);

    $services->set(RegistrationController::class)
        ->args([
            service(RegistrationHandlerInterface::class),
            service(BoundCookieFactoryInterface::class),
            service('security.token_storage'),
            service('clock'),
        ])
        ->tag('controller.service_arguments');

    $services->set(RefreshController::class)
        ->args([
            service(RefreshHandlerInterface::class),
            service(ChallengeManagerInterface::class),
            service(BoundCookieFactoryInterface::class),
            service('clock'),
        ])
        ->tag('controller.service_arguments');

    $services->set('dbsc.security.authenticator', DeviceBoundSessionAuthenticator::class)
        ->abstract()
        ->args([
            service(SessionBindingRepository::class),
            abstract_arg('user provider, set by the security factory'),
            '%dbsc.cookie.name%',
        ]);

    $services->set(DbscDataCollector::class)
        ->autoconfigure(false)
        ->args([
            service(AlgorithmProviderInterface::class),
            service(SessionBindingRepository::class),
            service(ChallengeStore::class),
            '%dbsc.cookie.name%',
            '%dbsc.registration.path%',
            '%dbsc.refresh.path%',
            '%dbsc.challenge.ttl%',
        ])
        ->tag('data_collector', [
            'id' => 'dbsc',
            'template' => '@SpomkyLabsDbsc/data_collector/dbsc.html.twig',
        ]);
};
