<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

/**
 * The outcome of a registration or refresh: the bound cookie value to set and the session
 * configuration document to return to the browser.
 */
final readonly class IssuedSession
{
    /**
     * @param array<string, mixed> $config the DBSC session configuration JSON
     */
    public function __construct(
        public string $sessionIdentifier,
        public string $cookieValue,
        public array $config,
    ) {
    }
}
