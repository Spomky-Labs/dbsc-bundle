<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle;

use function dirname;
use SpomkyLabs\DbscBundle\Security\Factory\DeviceBoundSessionFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
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
     * The bundle has no global configuration; everything is configured per firewall by
     * {@see DeviceBoundSessionFactory}. This only loads the shared services and guarantees the
     * cross-firewall plumbing exists even when no firewall enables DBSC.
     *
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

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
