# DBSC Bundle

Protect Symfony sessions from cookie theft by binding them to a key held in the device hardware.
Even if a session or remember-me cookie is stolen, it stops working on the thief's machine.

## How it works, in short

- At login, the bundle asks a supporting browser to create a device-bound key (kept in the TPM).
- The browser proves it holds that key to get a short-lived cookie, and re-proves it on every
  refresh.
- A copied cookie cannot be refreshed from another device, so it stops working within minutes.

The browser does all the cryptography. Your app just enables the feature on a firewall; the bundle
emits one header at login and answers two endpoints. Browsers that do not support DBSC ignore it
and keep working exactly as before; adopting the bundle is risk-free.

## Quick start

The no-fuss setup: **additive mode**, a device-bound cookie issued alongside your normal session,
which stays in charge. Nothing about how users are authenticated changes.

**1. Install** (Symfony Flex registers the bundle automatically):

```bash
composer require spomky-labs/dbsc-bundle
```

**2. Import the routes:**

```yaml
# config/routes/dbsc.yaml
dbsc:
    resource: '@SpomkyLabsDbscBundle/config/routes.php'
```

**3. Enable it on your firewall and open its two endpoints:**

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session: true
    access_control:
        - { path: ^/dbsc/main/refresh, roles: PUBLIC_ACCESS }
        - { path: ^/dbsc/main/register, roles: IS_AUTHENTICATED_FULLY }
```

**4. Request registration at login** by adding a badge to your authenticator's passport, exactly
like remember-me:

```php
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;

return new SelfValidatingPassport(
    new UserBadge($userIdentifier),
    [new DeviceBoundSessionBadge()],
);
```

That's the whole base setup. A supporting browser now registers a device-bound cookie when the user
opts in with a `_device_bound_session` checkbox at login. [Additive mode](additive-mode.md) explains
the badge, the checkbox and the `always` option.

## Going further

Each topic has its own page; pick what you need.

| You want to… | Read |
| --- | --- |
| Understand what DBSC is and what it protects | [Concepts & security model](concepts.md) |
| Check requirements and registration | [Installation](installation.md) |
| Start safely (cookie alongside your session) | [Additive mode](additive-mode.md) |
| Replace remember-me with a device-bound credential | [Long-lived credential](replacement-mode.md) |
| Tune cookies, algorithms, endpoints or stores | [Configuration reference](configuration.md) |
| Go to production (shared, persistent stores) | [Production storage](storage.md) |
| Customise internals or accept another algorithm | [Extending the bundle](extending.md) |
| Inspect the wire protocol | [Protocol & endpoints](protocol.md) |
