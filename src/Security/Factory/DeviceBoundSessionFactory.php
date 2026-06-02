<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Wires Device Bound Session Credentials on a firewall.
 *
 * It always registers, on the firewall's event dispatcher, the conditions listener (which
 * enables the badge either always or from a checkbox parameter) and the registration-header
 * listener. When `authenticate` is true it additionally registers the device-bound
 * authenticator, turning the bound cookie into the long-lived credential (remember-me
 * replacement); otherwise the firewall keeps authenticating as before (additive mode).
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
            ->scalarNode('cookie_name')
            ->info('Override the bound-cookie name for this firewall. Defaults to dbsc.cookie.name.')
            ->defaultNull()
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
        $dispatcher = 'security.event_dispatcher.' . $firewallName;

        $conditionsId = 'security.listener.device_bound_session_conditions.' . $firewallName;
        $container->setDefinition($conditionsId, new ChildDefinition('dbsc.security.conditions_listener'))
            ->replaceArgument(0, $config['always'])
            ->replaceArgument(1, $config['checkbox'])
            ->addTag('kernel.event_listener', [
                'event' => LoginSuccessEvent::class,
                'method' => 'onLoginSuccess',
                'priority' => -32,
                'dispatcher' => $dispatcher,
            ]);

        $headerId = 'security.listener.device_bound_session_header.' . $firewallName;
        $container->setDefinition($headerId, new ChildDefinition('dbsc.security.header_listener'))
            ->addTag('kernel.event_listener', [
                'event' => LoginSuccessEvent::class,
                'method' => 'onLoginSuccess',
                'priority' => -64,
                'dispatcher' => $dispatcher,
            ]);

        if ($config['authenticate'] !== true) {
            return [];
        }

        $authenticatorId = 'security.authenticator.device_bound_session.' . $firewallName;
        $definition = new ChildDefinition('dbsc.security.authenticator');
        $definition->replaceArgument(1, new Reference($userProviderId));
        if (($config['cookie_name'] ?? null) !== null) {
            $definition->replaceArgument(2, $config['cookie_name']);
        }
        $container->setDefinition($authenticatorId, $definition);

        return $authenticatorId;
    }
}
