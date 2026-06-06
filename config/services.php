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
use SpomkyLabs\DbscBundle\Challenge\ChallengeManager;
use SpomkyLabs\DbscBundle\Challenge\InMemoryChallengeStore;
use SpomkyLabs\DbscBundle\Controller\RefreshController;
use SpomkyLabs\DbscBundle\Controller\RegistrationController;
use SpomkyLabs\DbscBundle\DataCollector\DbscDataCollector;
use SpomkyLabs\DbscBundle\EventListener\DeviceBoundSessionConditionsListener;
use SpomkyLabs\DbscBundle\EventListener\DeviceBoundSessionLogoutListener;
use SpomkyLabs\DbscBundle\EventListener\RegistrationHeaderListener;
use SpomkyLabs\DbscBundle\EventListener\SecureSessionSkippedListener;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactory;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProvider;
use SpomkyLabs\DbscBundle\Jwt\DeviceProofVerifier;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandler;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandler;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactory;
use SpomkyLabs\DbscBundle\Protocol\TokenGenerator;
use SpomkyLabs\DbscBundle\Protocol\TokenGeneratorInterface;
use SpomkyLabs\DbscBundle\Routing\DbscRouteLoader;
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionAuthenticator;
use SpomkyLabs\DbscBundle\Session\InMemorySessionBindingRepository;
use function Symfony\Component\DependencyInjection\Loader\Configurator\abstract_arg;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure();

    // JWS algorithms are shared services; each firewall selects which ones it accepts.
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

    // Stateless, configuration-free service shared by every firewall.
    $services->set(TokenGenerator::class);
    $services->alias(TokenGeneratorInterface::class, TokenGenerator::class);

    // Firewall-agnostic: logs the `Secure-Session-Skipped` header on any incoming request.
    $services->set(SecureSessionSkippedListener::class)
        ->args([service('logger')->nullOnInvalid()])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.request',
            'method' => 'onKernelRequest',
        ]);

    $services->set('dbsc.algorithm_provider', AlgorithmProvider::class)
        ->abstract()
        ->args([
            tagged_iterator('dbsc.jose_algorithm'),
            abstract_arg('accepted algorithm names, set by the security factory'),
        ]);

    $services->set('dbsc.device_proof_verifier', DeviceProofVerifier::class)
        ->abstract()
        ->args([abstract_arg('algorithm provider, set by the security factory')]);

    $services->set('dbsc.challenge_store', InMemoryChallengeStore::class)
        ->abstract()
        ->args([service('clock')]);

    $services->set('dbsc.challenge_manager', ChallengeManager::class)
        ->abstract()
        ->args([
            abstract_arg('challenge store, set by the security factory'),
            service('clock'),
            abstract_arg('challenge ttl, set by the security factory'),
        ]);

    $services->set('dbsc.binding_repository', InMemorySessionBindingRepository::class)
        ->abstract();

    $services->set('dbsc.bound_cookie_factory', BoundCookieFactory::class)
        ->abstract()
        ->args([abstract_arg('cookie config, set by the security factory')]);

    $services->set('dbsc.session_config_factory', SessionConfigFactory::class)
        ->abstract()
        ->args([
            abstract_arg('refresh path, set by the security factory'),
            abstract_arg('cookie config, set by the security factory'),
            abstract_arg('scope exclude paths, set by the security factory'),
            abstract_arg('include_site flag, set by the security factory'),
            abstract_arg('allowed refresh initiators, set by the security factory'),
        ]);

    $services->set('dbsc.registration_handler', RegistrationHandler::class)
        ->abstract()
        ->args([
            abstract_arg('device proof verifier, set by the security factory'),
            abstract_arg('challenge manager, set by the security factory'),
            abstract_arg('binding repository, set by the security factory'),
            abstract_arg('session config factory, set by the security factory'),
            service(TokenGeneratorInterface::class),
            service('clock'),
        ]);

    $services->set('dbsc.refresh_handler', RefreshHandler::class)
        ->abstract()
        ->args([
            abstract_arg('device proof verifier, set by the security factory'),
            abstract_arg('challenge manager, set by the security factory'),
            abstract_arg('binding repository, set by the security factory'),
            abstract_arg('session config factory, set by the security factory'),
            service(TokenGeneratorInterface::class),
            service('clock'),
            abstract_arg('session lifetime, set by the security factory'),
        ]);

    $services->set('dbsc.registration_controller', RegistrationController::class)
        ->abstract()
        ->args([
            abstract_arg('registration handler, set by the security factory'),
            abstract_arg('bound cookie factory, set by the security factory'),
            service('security.token_storage'),
            service('clock'),
        ]);

    $services->set('dbsc.refresh_controller', RefreshController::class)
        ->abstract()
        ->args([
            abstract_arg('refresh handler, set by the security factory'),
            abstract_arg('challenge manager, set by the security factory'),
            abstract_arg('bound cookie factory, set by the security factory'),
            service('clock'),
            abstract_arg('session config factory, set by the security factory'),
        ]);

    $services->set('dbsc.security.conditions_listener', DeviceBoundSessionConditionsListener::class)
        ->abstract()
        ->args([
            abstract_arg('always, set by the security factory'),
            abstract_arg('checkbox parameter, set by the security factory'),
        ]);

    $services->set('dbsc.security.header_listener', RegistrationHeaderListener::class)
        ->abstract()
        ->args([
            abstract_arg('challenge manager, set by the security factory'),
            abstract_arg('algorithm provider, set by the security factory'),
            abstract_arg('registration path, set by the security factory'),
        ]);

    $services->set('dbsc.security.logout_listener', DeviceBoundSessionLogoutListener::class)
        ->abstract()
        ->args([
            abstract_arg('binding repository, set by the security factory'),
            abstract_arg('bound cookie factory, set by the security factory'),
        ]);

    $services->set('dbsc.security.authenticator', DeviceBoundSessionAuthenticator::class)
        ->abstract()
        ->args([
            abstract_arg('binding repository, set by the security factory'),
            abstract_arg('user provider, set by the security factory'),
            abstract_arg('cookie name, set by the security factory'),
            service('security.token_storage'),
        ]);

    // --- Cross-firewall infrastructure ------------------------------------------------------
    // The route loader turns the firewalls map into one register/refresh route pair per
    // firewall; the data collector aggregates the per-firewall stores for the profiler.

    $services->set(DbscRouteLoader::class)
        ->autowire(false)
        ->args([param('dbsc.firewalls')])
        ->tag('routing.loader');

    $services->set(DbscDataCollector::class)
        ->autoconfigure(false)
        ->args([
            param('dbsc.firewalls'),
            service('dbsc.firewall_repositories'),
            service('dbsc.firewall_challenge_stores'),
        ])
        ->tag('data_collector', [
            'id' => 'dbsc',
            'template' => '@SpomkyLabsDbsc/data_collector/dbsc.html.twig',
        ]);
};
