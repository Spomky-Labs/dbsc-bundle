<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests;

use SpomkyLabs\DbscBundle\SpomkyLabsDbscBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\HttpKernel\Kernel;

/**
 * @internal
 */
final class AppKernel extends Kernel
{
    public function __construct(string $environment)
    {
        parent::__construct($environment, false);
    }

    /**
     * @return BundleInterface[]
     */
    public function registerBundles(): array
    {
        return [new FrameworkBundle(), new SecurityBundle(), new SpomkyLabsDbscBundle()];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/config.php');
    }
}
