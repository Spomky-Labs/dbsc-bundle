<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * Builds the DBSC session configuration document returned from the endpoints.
 */
interface SessionConfigFactoryInterface
{
    /**
     * @return array<string, mixed>
     */
    public function create(string $sessionIdentifier, string $origin): array;
}
