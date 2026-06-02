<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle;

use function dirname;
use SpomkyLabs\DbscBundle\Security\Factory\DeviceBoundSessionFactory;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
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

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->import('../config/config.php');
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        /** @var list<string> $algorithms */
        $algorithms = $config['algorithms'];
        $builder->setParameter('dbsc.algorithms', $algorithms);

        /** @var string $registration */
        $registration = $config['registration'];
        $builder->setParameter('dbsc.registration.path', $registration);

        /** @var string $refresh */
        $refresh = $config['refresh'];
        $builder->setParameter('dbsc.refresh.path', $refresh);

        /** @var int $challengeTtl */
        $challengeTtl = $config['challenge_ttl'];
        $builder->setParameter('dbsc.challenge.ttl', $challengeTtl);

        /** @var array{name: string} $cookie */
        $cookie = $config['cookie'];
        $builder->setParameter('dbsc.cookie', $cookie);
        $builder->setParameter('dbsc.cookie.name', $cookie['name']);

        /** @var string|null $bindingRepository */
        $bindingRepository = $config['binding_repository'];
        if ($bindingRepository !== null) {
            $builder->setAlias(SessionBindingRepository::class, $bindingRepository);
        }
    }
}
