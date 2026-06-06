<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Wires Device Bound Session Credentials on a firewall.
 *
 * All configuration is per firewall: the factory builds a self-contained graph of
 * firewall-scoped services (algorithm provider, proof verifier, challenge store/manager,
 * binding repository, cookie factory, handlers and controllers) from the abstract templates
 * in config/services.php, and records the firewall in the `dbsc.firewalls` parameter so the
 * route loader and the profiler collector can pick it up.
 *
 * It always registers the conditions listener (which enables the badge either always or from a
 * checkbox parameter) and the registration-header listener on the firewall's dispatcher. When
 * `authenticate` is true it additionally registers the device-bound authenticator, turning the
 * bound cookie into the long-lived credential (remember-me replacement); otherwise the firewall
 * keeps authenticating as before (additive mode).
 */
final class DeviceBoundSessionFactory implements AuthenticatorFactoryInterface
{
    public const PRIORITY = -45;

    /**
     * Just above remember-me: a passive credential that must not pre-empt interactive
     * authenticators (form_login, json_login, WebAuthn) on the login route.
     */
    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getKey(): string
    {
        return 'device_bound_session';
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        if (! $builder instanceof ArrayNodeDefinition) {
            return;
        }

        $builder
            ->canBeUnset()
            ->treatTrueLike([])
            ->treatNullLike([])
            ->children()
            ->booleanNode('always')
            ->info('Always request device-bound registration at login.')
            ->defaultFalse()
            ->end()
            ->scalarNode('checkbox')
            ->info('Request parameter (checkbox input name) that opts in to registration when "always" is false.')
            ->defaultValue('_device_bound_session')
            ->end()
            ->booleanNode('authenticate')
            ->info(
                'Authenticate requests from the device-bound cookie (remember-me replacement). False keeps the additive mode.'
            )
            ->defaultFalse()
            ->end()
            ->arrayNode('algorithms')
            ->info('Accepted JWS signature algorithms for the device-bound key. DBSC mandates ES256 and RS256.')
            ->scalarPrototype()
            ->end()
            ->defaultValue(['ES256', 'RS256'])
            ->end()
            ->scalarNode('binding_repository')
            ->info('Service id of a persistent SessionBindingRepository. Null keeps a per-firewall in-memory store.')
            ->defaultNull()
            ->end()
            ->scalarNode('challenge_store')
            ->info('Service id of a persistent ChallengeStore. Null keeps a per-firewall in-memory store.')
            ->defaultNull()
            ->end()
            ->integerNode('challenge_ttl')
            ->info('Lifetime of a single-use challenge, in seconds.')
            ->defaultValue(300)
            ->end()
            ->integerNode('session_lifetime')
            ->info(
                'Lifetime of the device-bound credential (the binding), in seconds, independent of the cookie. Null never expires.'
            )
            ->defaultNull()
            ->end()
            ->arrayNode('scope_exclude_paths')
            ->info(
                'Paths kept out of the session scope (e.g. /assets, /build) so their requests never trigger a refresh.'
            )
            ->scalarPrototype()
            ->end()
            ->defaultValue([])
            ->end()
            ->booleanNode('include_site')
            ->info(
                'Emit a site-scoped session (include_site: true) instead of origin-scoped. Origin-scoped is the safer default.'
            )
            ->defaultFalse()
            ->end()
            ->arrayNode('allowed_refresh_initiators')
            ->info(
                'Origins allowed to initiate a refresh (e.g. embedded cross-origin contexts). Emitted as allowed_refresh_initiators; empty omits it.'
            )
            ->example(['https://app.example.com', 'https://admin.example.com:8443'])
            ->scalarPrototype()
            ->end()
            ->defaultValue([])
            ->end()
            ->scalarNode('register')
            ->info('Path of the registration endpoint. Null derives /dbsc/<firewall>/register.')
            ->defaultNull()
            ->end()
            ->scalarNode('refresh')
            ->info('Path of the refresh endpoint. Null derives /dbsc/<firewall>/refresh.')
            ->defaultNull()
            ->end()
            ->arrayNode('cookie')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('name')
            ->info(
                'Name of the short-lived device-bound cookie. The spec allows a __Host-/__Secure- prefix (e.g. __Host-dbsc_session); a __Host- name additionally requires secure=true, path=/ and no domain. The default stays unprefixed for the broadest compatibility — set a prefixed name explicitly if you want those guarantees.'
            )
            ->defaultValue('dbsc_session')
            ->end()
            ->integerNode('lifetime')
            ->info('Lifetime of the bound cookie, in seconds.')
            ->defaultValue(600)
            ->end()
            ->scalarNode('path')
            ->defaultValue('/')
            ->end()
            ->scalarNode('domain')
            ->defaultNull()
            ->end()
            ->booleanNode('secure')
            ->defaultTrue()
            ->end()
            ->booleanNode('http_only')
            ->defaultTrue()
            ->end()
            ->enumNode('same_site')
            ->values(['lax', 'strict', 'none'])
            ->defaultValue('lax')
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return string|array<int, string>
     */
    public function createAuthenticator(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $userProviderId
    ): string|array {
        /** @var list<string> $algorithms */
        $algorithms = $config['algorithms'];
        /** @var array{name: string, lifetime: int, path: string, domain: string|null, secure: bool, http_only: bool, same_site: string} $cookie */
        $cookie = $config['cookie'];
        /** @var int $challengeTtl */
        $challengeTtl = $config['challenge_ttl'];
        /** @var int|null $sessionLifetime */
        $sessionLifetime = $config['session_lifetime'];
        /** @var list<string> $excludePaths */
        $excludePaths = $config['scope_exclude_paths'];
        /** @var bool $includeSite */
        $includeSite = $config['include_site'];
        /** @var list<string> $allowedRefreshInitiators */
        $allowedRefreshInitiators = $config['allowed_refresh_initiators'];
        /** @var string|null $bindingRepository */
        $bindingRepository = $config['binding_repository'];
        /** @var string|null $challengeStore */
        $challengeStore = $config['challenge_store'];

        $registerPath = $config['register'] ?? '/dbsc/' . $firewallName . '/register';
        $refreshPath = $config['refresh'] ?? '/dbsc/' . $firewallName . '/refresh';

        $algorithmProviderId = 'dbsc.algorithm_provider.' . $firewallName;
        $container->setDefinition($algorithmProviderId, new ChildDefinition('dbsc.algorithm_provider'))
            ->replaceArgument(1, $algorithms);

        $verifierId = 'dbsc.device_proof_verifier.' . $firewallName;
        $container->setDefinition($verifierId, new ChildDefinition('dbsc.device_proof_verifier'))
            ->replaceArgument(0, new Reference($algorithmProviderId));

        $challengeStoreId = 'dbsc.challenge_store.' . $firewallName;
        if ($challengeStore !== null) {
            $container->setAlias($challengeStoreId, $challengeStore);
        } else {
            $container->setDefinition($challengeStoreId, new ChildDefinition('dbsc.challenge_store'));
        }

        $challengeManagerId = 'dbsc.challenge_manager.' . $firewallName;
        $container->setDefinition($challengeManagerId, new ChildDefinition('dbsc.challenge_manager'))
            ->replaceArgument(0, new Reference($challengeStoreId))
            ->replaceArgument(2, $challengeTtl);

        $repositoryId = 'dbsc.binding_repository.' . $firewallName;
        if ($bindingRepository !== null) {
            $container->setAlias($repositoryId, $bindingRepository);
        } else {
            $container->setDefinition($repositoryId, new ChildDefinition('dbsc.binding_repository'));
        }

        $cookieFactoryId = 'dbsc.bound_cookie_factory.' . $firewallName;
        $container->setDefinition($cookieFactoryId, new ChildDefinition('dbsc.bound_cookie_factory'))
            ->replaceArgument(0, $cookie);

        $sessionConfigId = 'dbsc.session_config_factory.' . $firewallName;
        $container->setDefinition($sessionConfigId, new ChildDefinition('dbsc.session_config_factory'))
            ->replaceArgument(0, $refreshPath)
            ->replaceArgument(1, $cookie)
            ->replaceArgument(2, $excludePaths)
            ->replaceArgument(3, $includeSite)
            ->replaceArgument(4, $allowedRefreshInitiators);

        $registrationHandlerId = 'dbsc.registration_handler.' . $firewallName;
        $container->setDefinition($registrationHandlerId, new ChildDefinition('dbsc.registration_handler'))
            ->replaceArgument(0, new Reference($verifierId))
            ->replaceArgument(1, new Reference($challengeManagerId))
            ->replaceArgument(2, new Reference($repositoryId))
            ->replaceArgument(3, new Reference($sessionConfigId));

        $refreshHandlerId = 'dbsc.refresh_handler.' . $firewallName;
        $container->setDefinition($refreshHandlerId, new ChildDefinition('dbsc.refresh_handler'))
            ->replaceArgument(0, new Reference($verifierId))
            ->replaceArgument(1, new Reference($challengeManagerId))
            ->replaceArgument(2, new Reference($repositoryId))
            ->replaceArgument(3, new Reference($sessionConfigId))
            ->replaceArgument(6, $sessionLifetime);

        $registrationControllerId = 'dbsc.registration_controller.' . $firewallName;
        $container->setDefinition($registrationControllerId, new ChildDefinition('dbsc.registration_controller'))
            ->replaceArgument(0, new Reference($registrationHandlerId))
            ->replaceArgument(1, new Reference($cookieFactoryId))
            ->addTag('controller.service_arguments');

        $refreshControllerId = 'dbsc.refresh_controller.' . $firewallName;
        $container->setDefinition($refreshControllerId, new ChildDefinition('dbsc.refresh_controller'))
            ->replaceArgument(0, new Reference($refreshHandlerId))
            ->replaceArgument(1, new Reference($challengeManagerId))
            ->replaceArgument(2, new Reference($cookieFactoryId))
            ->replaceArgument(4, new Reference($sessionConfigId))
            ->addTag('controller.service_arguments');

        $dispatcher = 'security.event_dispatcher.' . $firewallName;

        $conditionsId = 'dbsc.security.conditions_listener.' . $firewallName;
        $container->setDefinition($conditionsId, new ChildDefinition('dbsc.security.conditions_listener'))
            ->replaceArgument(0, $config['always'])
            ->replaceArgument(1, $config['checkbox'])
            ->addTag('kernel.event_listener', [
                'event' => LoginSuccessEvent::class,
                'method' => 'onLoginSuccess',
                'priority' => -32,
                'dispatcher' => $dispatcher,
            ]);

        $headerId = 'dbsc.security.header_listener.' . $firewallName;
        $container->setDefinition($headerId, new ChildDefinition('dbsc.security.header_listener'))
            ->replaceArgument(0, new Reference($challengeManagerId))
            ->replaceArgument(1, new Reference($algorithmProviderId))
            ->replaceArgument(2, $registerPath)
            ->addTag('kernel.event_listener', [
                'event' => LoginSuccessEvent::class,
                'method' => 'onLoginSuccess',
                'priority' => -64,
                'dispatcher' => $dispatcher,
            ]);

        $logoutId = 'dbsc.security.logout_listener.' . $firewallName;
        $container->setDefinition($logoutId, new ChildDefinition('dbsc.security.logout_listener'))
            ->replaceArgument(0, new Reference($repositoryId))
            ->replaceArgument(1, new Reference($cookieFactoryId))
            ->addTag('kernel.event_listener', [
                'event' => LogoutEvent::class,
                'method' => 'onLogout',
                'dispatcher' => $dispatcher,
            ]);

        $this->registerInLocator($container, 'dbsc.firewall_repositories', $firewallName, $repositoryId);
        $this->registerInLocator($container, 'dbsc.firewall_challenge_stores', $firewallName, $challengeStoreId);

        /** @var array<string, mixed> $firewalls */
        $firewalls = $container->hasParameter('dbsc.firewalls') ? $container->getParameter('dbsc.firewalls') : [];
        $firewalls[$firewallName] = [
            'register' => $registerPath,
            'refresh' => $refreshPath,
            'registration_controller' => $registrationControllerId,
            'refresh_controller' => $refreshControllerId,
            'cookie_name' => $cookie['name'],
            'cookie' => $cookie,
            'algorithms' => $algorithms,
            'challenge_ttl' => $challengeTtl,
            'session_lifetime' => $sessionLifetime,
            'authenticate' => $config['authenticate'] === true,
            'always' => $config['always'] === true,
            'checkbox' => $config['checkbox'],
            'include_site' => $includeSite,
            'scope_exclude_paths' => $excludePaths,
            'allowed_refresh_initiators' => $allowedRefreshInitiators,
            'binding_repository_service' => $bindingRepository,
            'challenge_store_service' => $challengeStore,
        ];
        $container->setParameter('dbsc.firewalls', $firewalls);

        if ($config['authenticate'] !== true) {
            return [];
        }

        $authenticatorId = 'dbsc.security.authenticator.' . $firewallName;
        $container->setDefinition($authenticatorId, new ChildDefinition('dbsc.security.authenticator'))
            ->replaceArgument(0, new Reference($repositoryId))
            ->replaceArgument(1, new Reference($userProviderId))
            ->replaceArgument(2, $cookie['name']);

        return $authenticatorId;
    }

    /**
     * Appends a firewall-scoped service to a service locator (keyed by firewall name), creating
     * the locator on the first firewall. Consumed by the profiler data collector.
     */
    private function registerInLocator(
        ContainerBuilder $container,
        string $locatorId,
        string $firewallName,
        string $serviceId
    ): void {
        if ($container->hasDefinition($locatorId)) {
            $locator = $container->getDefinition($locatorId);
            /** @var array<string, Reference> $map */
            $map = $locator->getArgument(0);
        } else {
            $locator = new Definition(ServiceLocator::class, [[]]);
            $locator->addTag('container.service_locator');
            $container->setDefinition($locatorId, $locator);
            $map = [];
        }

        $map[$firewallName] = new Reference($serviceId);
        $locator->replaceArgument(0, $map);
    }
}
