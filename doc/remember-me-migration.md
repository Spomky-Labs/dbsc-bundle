# Migrating from remember-me to DBSC

DBSC plays the same role as Symfony's remember-me — it re-authenticates a returning user once the
active session has expired — but with a credential bound to the device instead of a static,
replayable cookie. The two are deliberately close, so the move is mostly a one-badge swap plus a
firewall option.

The migration is **gradual and reversible**, and it never needs a data migration: the binding store
records the user identifier and rotating token from the very first registration. Because DBSC only
works on supporting browsers, keep remember-me in place as a fallback until your coverage is high
enough to drop it — unsupported browsers then keep working unchanged throughout.

## What maps to what

| Remember-me | DBSC | Notes |
| --- | --- | --- |
| `remember_me` firewall key | `device_bound_session` | both under the same firewall |
| `RememberMeBadge` | `DeviceBoundSessionBadge` | added to the passport the same way |
| `always_remember_me` | `always` | register at every login |
| `remember_me_parameter` (`_remember_me`) | `checkbox` (`_device_bound_session`) | the opt-in form control |
| `lifetime` (e.g. `604800`) | `session_lifetime` | how long the durable credential lasts |
| the remember-me cookie | the bound cookie (short) + the binding | `cookie.lifetime` is short; the binding carries the durable part |
| `IS_AUTHENTICATED_REMEMBERED` | `IS_AUTHENTICATED_REMEMBERED` | identical; `IS_AUTHENTICATED_FULLY` still needs a fresh login |
| cookie + token cleared on logout | automatic | a `LogoutEvent` listener clears the cookie and deletes the binding |

## Starting point

A typical remember-me firewall:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800 # 7 days
                token_provider:
                    doctrine: true
```

with the badge in your authenticator and a `_remember_me` checkbox in the login form:

```php
return new SelfValidatingPassport(
    new UserBadge($userIdentifier),
    [new RememberMeBadge()],
);
```

## Step 1 — Install and wire the bundle

```bash
composer require spomky-labs/dbsc-bundle
```

Import the routes once (see [Installation](installation.md#routes)):

```yaml
# config/routes/dbsc.yaml
dbsc:
    resource: '@SpomkyLabsDbscBundle/config/routes.php'
```

## Step 2 — Run DBSC next to remember-me (additive)

Enable DBSC on the same firewall in additive mode (`authenticate: false`, the default), keeping
remember-me untouched. Reuse the existing checkbox so a single "keep me signed in" control drives
both:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800
                token_provider:
                    doctrine: true
            device_bound_session:
                checkbox: _remember_me   # reuse the remember-me form control
    access_control:
        - { path: ^/dbsc/main/refresh, roles: PUBLIC_ACCESS }
        - { path: ^/dbsc/main/register, roles: IS_AUTHENTICATED_FULLY }
```

Add the DBSC badge **alongside** the remember-me badge in the passport:

```php
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;

return new SelfValidatingPassport(
    new UserBadge($userIdentifier),
    [new RememberMeBadge(), new DeviceBoundSessionBadge()],
);
```

Now supporting browsers register a device-bound cookie while everyone keeps their remember-me
cookie. Nothing about authentication changes yet. Watch real-world coverage in the web profiler's
DBSC panel before going further. See [Additive mode](additive-mode.md).

## Step 3 — Let DBSC take over the credential (replacement)

Flip `authenticate` to true and set `session_lifetime` to match the old remember-me `lifetime`:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800
                token_provider:
                    doctrine: true
            device_bound_session:
                checkbox: _remember_me
                authenticate: true
                session_lifetime: 604800   # mirror the remember-me lifetime (7 days)
```

On a supporting browser the returning user is now re-authenticated from the device-bound cookie
(`IS_AUTHENTICATED_REMEMBERED`), and a stolen cookie is useless on another device. On every other
browser remember-me still provides the fallback, so no one is logged out by the change. The binding
store already holds everything from step 2, so there is no data migration.

To keep the session itself short (so DBSC carries the durable part rather than a long session
cookie), see the layering in [Device-bound long-lived credential](replacement-mode.md#recommended-layering).

## Step 4 — Retire remember-me (optional)

Once the profiler shows your users are overwhelmingly on supporting browsers, drop remember-me. From
then on, browsers without DBSC simply require an interactive login again after their session
expires — the normal, safe behaviour:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                checkbox: _remember_me
                authenticate: true
                session_lifetime: 604800
```

Remove the `RememberMeBadge` from the passport, leaving only the `DeviceBoundSessionBadge`:

```php
return new SelfValidatingPassport(
    new UserBadge($userIdentifier),
    [new DeviceBoundSessionBadge()],
);
```

You may also remove the remember-me `token_provider` table once no remember-me cookies remain in
the wild.

## Things that do not change

- **Authentication level.** DBSC grants `IS_AUTHENTICATED_REMEMBERED`, exactly like remember-me, so
  guards requiring `IS_AUTHENTICATED_FULLY` (password change, payment, admin) still force a fresh
  login on a known device.
- **Your user provider and login method.** The binding stores the identifier of whoever logged in
  (password, WebAuthn, SSO…) and reloads the user by identifier; there is no coupling to a login
  mechanism.
- **Logout.** Cleanup is automatic — no wiring, like remember-me.
