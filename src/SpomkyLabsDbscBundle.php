<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle;

use function dirname;
use SpomkyLabs\DbscBundle\Controller\WellKnownController;
use SpomkyLabs\DbscBundle\Protocol\WellKnownDocumentFactory;
use SpomkyLabs\DbscBundle\Routing\DbscRouteLoader;
use SpomkyLabs\DbscBundle\Security\Factory\DeviceBoundSessionFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class SpomkyLabsDbscBundle extends AbstractBundle
{
    protected string $extensionAlias = 'dbsc';

    public function getPath(): string
    {
        return dirname(__DIR__);
    }

    /**
     * Exposes the `device_bound_session` firewall key. The registration is guarded so the
     * bundle still works in additive mode without SecurityBundle's extension present.
     */
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        if ($container->hasExtension('security')) {
            $security = $container->getExtension('security');
            if ($security instanceof SecurityExtension) {
                $security->addAuthenticatorFactory(new DeviceBoundSessionFactory());
            }
        }
    }

    /**
     * The only global configuration is federation, because the `/.well-known/device-bound-sessions`
     * document is per origin, not per firewall. Everything else is configured per firewall by
     * {@see DeviceBoundSessionFactory}.
     */
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
            ->arrayNode('federation')
            ->info(
                'Federated sessions (key sharing). Serves /.well-known/device-bound-sessions. A site is either a relying party (provider_origin) or a session provider (relying_origins), never both.'
            )
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('provider_origin')
            ->info('Relying party: origin of the session provider whose device keys this site reuses.')
            ->defaultNull()
            ->end()
            ->arrayNode('relying_origins')
            ->info('Session provider: origins allowed to register sessions sharing this site\'s device keys.')
            ->scalarPrototype()
            ->end()
            ->defaultValue([])
            ->end()
            ->arrayNode('registering_origins')
            ->info('Session provider: origins allowed to register site-scoped sessions on this site (optional).')
            ->scalarPrototype()
            ->end()
            ->defaultValue([])
            ->end()
            ->end()
            ->end()
            ->end();
    }

    /**
     * Loads the shared services, guarantees the cross-firewall plumbing exists even when no
     * firewall enables DBSC, and registers the well-known controller when federation is
     * configured.
     *
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        /** @var array{provider_origin: string|null, relying_origins: list<string>, registering_origins: list<string>} $federation */
        $federation = $config['federation'];
        $document = WellKnownDocumentFactory::create(
            $federation['provider_origin'],
            $federation['relying_origins'],
            $federation['registering_origins'],
        );
        $builder->setParameter('dbsc.well_known_document', $document);
        $builder->getDefinition(DbscRouteLoader::class)
            ->replaceArgument(1, $document !== null);
        if ($document !== null) {
            $builder->register(WellKnownController::class)
                ->setArguments([$document])
                ->addTag('controller.service_arguments');
        }

        if (! $builder->hasParameter('dbsc.firewalls')) {
            $builder->setParameter('dbsc.firewalls', []);
        }

        foreach (['dbsc.firewall_repositories', 'dbsc.firewall_challenge_stores'] as $locatorId) {
            if (! $builder->hasDefinition($locatorId)) {
                $locator = new Definition(ServiceLocator::class, [[]]);
                $locator->addTag('container.service_locator');
                $builder->setDefinition($locatorId, $locator);
            }
        }
    }
}
