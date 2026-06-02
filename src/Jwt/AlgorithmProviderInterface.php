<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

use Jose\Component\Core\AlgorithmManager;

/**
 * Provides the JWS algorithm manager and the list of accepted algorithm names.
 */
interface AlgorithmProviderInterface
{
    public function getManager(): AlgorithmManager;

    /**
     * @return list<string>
     */
    public function getAllowedNames(): array;
}
