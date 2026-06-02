<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Session;

/**
 * Persists session ↔ device-key bindings.
 *
 * Implementations decide on storage (database, cache…). For production multi-node
 * deployments the store MUST be shared across nodes. A Doctrine ORM implementation can be
 * wired through the `dbsc.binding_repository` configuration option.
 */
interface SessionBindingRepository
{
    public function save(SessionBinding $binding): void;

    public function findBySessionIdentifier(string $sessionIdentifier): ?SessionBinding;

    /**
     * Finds the binding whose current bound-cookie token matches the given value. Used by
     * the security authenticator to resolve the user from the device-bound cookie when it
     * replaces the long-lived session cookie entirely.
     */
    public function findByCookieToken(string $cookieToken): ?SessionBinding;

    public function deleteBySessionIdentifier(string $sessionIdentifier): void;
}
