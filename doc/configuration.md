# Configuration reference

All options live under the `dbsc` key. Every option has a sensible default, so an empty
configuration is valid. The full tree with its defaults:

```yaml
# config/packages/dbsc.yaml
dbsc:
    # Accepted JWS signature algorithms for the device-bound key.
    # DBSC mandates ES256 and RS256; only algorithms registered as services are usable.
    algorithms: ['ES256', 'RS256']

    # Service id of a persistent SessionBindingRepository implementation.
    # null keeps the in-memory default (suitable for a single process only).
    binding_repository: null

    registration: /dbsc/register
    refresh: /dbsc/refresh

    # Lifetime of a single-use challenge, in seconds.
    challenge_ttl: 300

    cookie:
        # Name of the short-lived device-bound cookie.
        name: '__Host-dbsc_session'
        # Lifetime of the bound cookie, in seconds.
        lifetime: 600
        path: '/'
        domain: null
        secure: true
        http_only: true
        same_site: 'lax'  # one of: lax, strict, none
```

## Options

### `algorithms`

The signature algorithms the server accepts on registration and refresh proofs. The list is
intersected with the algorithms that are actually registered as services (see
[Extending the bundle](extending.md#algorithms)). Keep it to `ES256` and `RS256` unless you
have a specific reason to widen it.

### `binding_repository`

The service id of your persistent binding store. Left at `null`, the bundle uses an in-memory
store that is wiped on every process and is not shared between nodes, which is fine for
development and tests only. See [Production storage](storage.md).

### `registration` and `refresh`

The paths of the two endpoints. They are referenced by the bundled routes and announced to the
browser in the session configuration, so changing them here is enough; do not hard-code the
paths elsewhere.

### `challenge_ttl`

How long an issued challenge stays valid, in seconds. Challenges are single use and consumed on
success. A short lifetime is recommended.

### `cookie`

The attributes of the short-lived device-bound cookie. The `__Host-` prefix requires `secure:
true`, `path: '/'` and no `domain`, which is the default and the recommended setting. `lifetime`
controls how often the browser refreshes; a short value (a few minutes) is typical.

## Per-firewall option

DBSC is enabled per firewall with a key under the firewall, not under `dbsc`. It registers the
registration listeners on that firewall and, optionally, the device-bound authenticator. The
full tree with its defaults:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                # Always request registration at login (ignores the checkbox).
                always: false
                # Request parameter (checkbox input name) that opts in when "always" is false.
                checkbox: _device_bound_session
                # Authenticate requests from the bound cookie (remember-me replacement).
                # false keeps the additive mode (the session stays authoritative).
                authenticate: false
                # Override the bound-cookie name for this firewall (defaults to dbsc.cookie.name).
                cookie_name: null
```

`device_bound_session: true` is shorthand for the block above with all defaults (additive mode,
opt-in by the `_device_bound_session` checkbox). The `always` and `checkbox` options mirror
Symfony's `always_remember_me` and `remember_me_parameter`. See
[Adoption modes](modes.md) for the two modes.
