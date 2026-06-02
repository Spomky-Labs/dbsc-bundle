# Additive mode

This is where you start. A short, device-bound cookie is issued alongside your existing
session, which stays authoritative. The registration header is emitted at login, the two
endpoints answer, and bindings are recorded. Your firewall keeps authenticating as before, and
unsupported browsers are unaffected. Use it to observe real-world coverage with zero risk before
changing how requests are authenticated.

## Enabling it

Enable DBSC on the firewall that handles login. With `authenticate: false` (the default) it only
wires the registration listeners, no authenticator:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                checkbox: _device_bound_session
```

## Opting in: the badge and its conditions

Registration mirrors remember-me. To request it, add a `DeviceBoundSessionBadge` to the
passport, the analogue of `RememberMeBadge`. In a custom authenticator, include it in the
passport badges, exactly as you would
[add remember-me support to a custom authenticator](https://symfony.com/doc/current/security/remember_me.html#add-remember-me-support-to-custom-authenticators):

```php
use SpomkyLabs\DbscBundle\Security\DeviceBoundSessionBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

public function authenticate(Request $request): Passport
{
    return new SelfValidatingPassport(
        new UserBadge($userIdentifier),
        [new DeviceBoundSessionBadge()],
    );
}
```

The badge alone is not enough: like remember-me, it must be enabled. The firewall `always` and
`checkbox` options (the analogues of `always_remember_me` and `remember_me_parameter`) control
that. With `always: true` every login registers; otherwise registration happens only when the
request carries the configured checkbox parameter, truthy. Replacing remember-me with DBSC is
therefore a one-badge swap.

## Access control for the endpoints

The two endpoints have opposite access requirements, so declare them explicitly:

```yaml
# config/packages/security.yaml
security:
    access_control:
        - { path: ^/dbsc/refresh, roles: PUBLIC_ACCESS }
        - { path: ^/dbsc/register, roles: IS_AUTHENTICATED_FULLY }
```

`register` runs right after an interactive login and binds the current user, so it must require
authentication. `refresh` is called when the session may already have expired and authenticates
through the device proof alone, so it must be publicly reachable. Place these rules before any
broader rule that would otherwise cover the same paths.

## Next step

When you are confident, let DBSC take over the long-lived credential. See
[Device-bound long-lived credential](replacement-mode.md).
