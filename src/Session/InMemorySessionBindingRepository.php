<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Session;

/**
 * Volatile binding store. Per-firewall default for dev/test; replace with a shared,
 * persistent store in production via the firewall's `binding_repository` option.
 */
final class InMemorySessionBindingRepository implements SessionBindingRepository
{
    /**
     * @var array<string, SessionBinding>
     */
    private array $bindings = [];

    public function save(SessionBinding $binding): void
    {
        $this->bindings[$binding->sessionIdentifier] = $binding;
    }

    public function findBySessionIdentifier(string $sessionIdentifier): ?SessionBinding
    {
        return $this->bindings[$sessionIdentifier] ?? null;
    }

    public function findByCookieToken(string $cookieToken): ?SessionBinding
    {
        foreach ($this->bindings as $binding) {
            if ($binding->cookieToken !== null && hash_equals($binding->cookieToken, $cookieToken)) {
                return $binding;
            }
        }

        return null;
    }

    public function deleteBySessionIdentifier(string $sessionIdentifier): void
    {
        unset($this->bindings[$sessionIdentifier]);
    }
}
