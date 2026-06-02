# Production storage

The bundle persists two kinds of state: the session bindings (which device key belongs to which
session and user) and the issued challenges. Both ship with in-memory implementations that are
wiped on every process and are not shared between nodes. They are meant for development and tests
only.

A production deployment, and any deployment running more than one process, must replace them with
shared, persistent stores.

## Session bindings

A binding holds the session identifier, the device public key, the user identifier and the
rotating cookie token. Implement
`SpomkyLabs\DbscBundle\Session\SessionBindingRepository`:

```php
interface SessionBindingRepository
{
    public function save(SessionBinding $binding): void;

    public function findBySessionIdentifier(string $sessionIdentifier): ?SessionBinding;

    public function findByCookieToken(string $cookieToken): ?SessionBinding;

    public function deleteBySessionIdentifier(string $sessionIdentifier): void;
}
```

`findByCookieToken` is on the hot path in the device-bound credential mode (it runs on every
authenticated request), so index the cookie-token column. Wire your implementation:

```yaml
# config/packages/dbsc.yaml
dbsc:
    binding_repository: App\Security\Dbsc\DoctrineSessionBindingRepository
```

A Doctrine implementation typically maps a small entity (session identifier as primary key, the
JWK as JSON, the user identifier, the cookie token, timestamps) and delegates the three lookups to
the entity manager. Rotating the cookie token on refresh is a single update.

## Challenges

Challenges are short-lived and single use. Implement
`SpomkyLabs\DbscBundle\Challenge\ChallengeStore`:

```php
interface ChallengeStore
{
    public function save(Challenge $challenge): void;

    public function get(string $value): ?Challenge;

    public function consume(string $value): void;
}
```

A cache pool (`Psr\Cache` or a Symfony cache adapter) backed by a shared store such as Redis is a
natural fit, with the challenge TTL as the cache item lifetime. Register your store as a service
and alias the interface to it:

```yaml
# config/services.yaml
services:
    App\Security\Dbsc\CacheChallengeStore: ~
    SpomkyLabs\DbscBundle\Challenge\ChallengeStore:
        alias: App\Security\Dbsc\CacheChallengeStore
```

## Why sharing matters

In the device-bound credential mode the refresh flow issues a challenge on one request and
verifies the signed proof on the next. With unshared stores those two requests can land on
different nodes and the challenge will not be found, breaking the refresh. A stale or
node-local binding likewise fails to authenticate. Always use a store reachable from every node.
