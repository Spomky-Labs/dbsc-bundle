<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Tests;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * @internal
 */
final readonly class SecuredController
{
    public function __construct(
        private Security $security,
    ) {
    }

    #[Route('/test-login', name: 'test_login')]
    #[Route('/secured/fully', name: 'secured_fully')]
    #[Route('/secured', name: 'secured')]
    public function __invoke(): Response
    {
        return new Response('hello ' . ($this->security->getUser()?->getUserIdentifier() ?? 'anonymous'));
    }
}
