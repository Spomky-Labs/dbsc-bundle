# Configuration reference

DBSC has **no global configuration**. Everything is configured per firewall, under the
`device_bound_session` key of the firewall that should use it. A firewall enables DBSC, and tunes
its endpoints, cookie, accepted algorithms and stores, in one place.

Every option has a sensible default, so `device_bound_session: true` is enough to start (additive
mode, opt-in by the `_device_bound_session` checkbox). The full tree with its defaults:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                # When to request registration at login
                # Always request registration at login (ignores the checkbox).
                always: false
                # Request parameter (checkbox input name) that opts in when "always" is false.
                checkbox: _device_bound_session

                # Adoption mode
                # Authenticate requests from the bound cookie (remember-me replacement).
                # false keeps the additive mode (the session stays authoritative).
                authenticate: false

                # Endpoints
                # Paths of the two endpoints. null derives /dbsc/<firewall>/{register,refresh}.
                register: null
                refresh: null

                # Protocol
                # Accepted JWS signature algorithms for the device-bound key.
                # DBSC mandates ES256 and RS256; only algorithms registered as services are usable.
                algorithms: ['ES256', 'RS256']
                # Lifetime of a single-use challenge, in seconds.
                challenge_ttl: 300

                # Lifetimes
                # Lifetime of the credential (the binding), in seconds, independent of the cookie.
                # null never expires.
                session_lifetime: null
                # Paths kept out of the session scope so their requests never trigger a refresh.
                scope_exclude_paths: []

                # Storage (null = per-firewall in-memory, dev/test only)
                binding_repository: null
                challenge_store: null

                # Bound cookie
                cookie:
                    name: 'dbsc_session'
                    lifetime: 600
                    path: '/'
                    domain: null
                    secure: true
                    http_only: true
                    same_site: 'lax'  # one of: lax, strict, none
```

## Options

### `always` and `checkbox`

When `always` is true, registration is requested at every login on this firewall. Otherwise it is
requested only when the login request carries the `checkbox` parameter (a ticked checkbox input).
They mirror Symfony's `always_remember_me` and `remember_me_parameter`. See
[Adoption modes](modes.md).

### `authenticate`

`false` (default) keeps the **additive mode**: the bound cookie is issued and refreshed, but the
session stays authoritative. `true` switches to **full replacement**: the device-bound
authenticator turns the bound cookie into the long-lived credential (a remember-me replacement).
See [Adoption modes](modes.md).

### `register` and `refresh`

The paths of the two endpoints, announced to the browser in the session configuration. Left at
`null`, they default to `/dbsc/<firewall>/register` and `/dbsc/<firewall>/refresh`, so two
firewalls never collide. Set them explicitly to choose your own URLs. The
[route loader](installation.md#routes) generates one route pair per firewall from these paths.

### `algorithms`

The signature algorithms this firewall accepts on registration and refresh proofs. The list is
intersected with the algorithms registered as services (see
[Extending the bundle](extending.md#algorithms)). Keep it to `ES256` and `RS256` unless you have a
specific reason to widen it.

### `challenge_ttl`

How long an issued challenge stays valid, in seconds. Challenges are single use and consumed on
success. A short lifetime is recommended.

### `session_lifetime`

How long the **credential** (the binding) stays valid, in seconds, independently of the cookie.
This is the durable, remember-me-like part: as long as the binding is valid, refreshes succeed and
the user stays signed in even across cookie expiries and browser restarts. Once
`createdAt + session_lifetime` is reached, the refresh endpoint terminates the session and the user
must log in interactively again. `null` (default) never expires.

Think of the two lifetimes as distinct knobs: `cookie.lifetime` (short, e.g. minutes) controls how
often the browser refreshes; `session_lifetime` (long, e.g. 30 days) controls how long the login
itself lasts.

### `scope_exclude_paths`

Paths kept out of the session scope, so requests to them never trigger a refresh. When the cookie
expires, the browser performs one deferred refresh per concurrent in-scope request before sending
it; on a page that loads many assets this produces a burst of refreshes. Excluding static-asset
paths removes most of that churn:

```yaml
scope_exclude_paths: ['/assets', '/build', '/bundles']
```

The refresh endpoint's own path is always excluded by the browser, so you do not need to list it.

### `binding_repository` and `challenge_store`

The service ids of your persistent stores for this firewall. Left at `null`, the bundle uses
in-memory stores that are wiped on every process and not shared between nodes, fine for
development and tests only. See [Production storage](storage.md).

### `cookie`

The attributes of the short-lived device-bound cookie. `lifetime` controls how often the browser
refreshes; a short value (a few minutes) is typical. Keep `secure: true`, `http_only: true` and an
appropriate `same_site`.

> **Do not use a cookie-prefix name.** A `__Host-` or `__Secure-` prefixed cookie is **rejected by
> the browser as a DBSC bound credential** (registration silently fails and no session is
> established). Use a plain name such as the default `dbsc_session`; the cookie is still `Secure`,
> `HttpOnly` and `SameSite`, and DBSC adds the device binding on top.

## Logout

Logout cleanup is automatic: a per-firewall `LogoutEvent` listener deletes the binding (so the
cookie can no longer be refreshed) and clears the bound cookie, exactly as Symfony's remember-me
clears its persistent token and cookie. No application wiring is required.

## Multiple firewalls

Because configuration is per firewall, each firewall gets its own isolated graph: its own cookie,
endpoints, algorithms and stores. Two firewalls can run DBSC in different modes side by side, for
example an additive `main` firewall and a full-replacement `api` firewall, without sharing any
state.
