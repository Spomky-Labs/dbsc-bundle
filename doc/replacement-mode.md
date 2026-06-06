# Device-bound long-lived credential

When you are confident, DBSC takes over the long-lived re-authentication credential: the role a
remember-me cookie normally plays. Instead of a static, replayable remember-me cookie, the
long-lived credential becomes a short, device-bound cookie that the browser silently re-proves
and rotates through the refresh endpoint.

This page assumes you already run [additive mode](additive-mode.md). If you are coming from
Symfony's remember-me, the [remember-me migration guide](remember-me-migration.md) walks the whole
move step by step, with a fallback-safe path for unsupported browsers.

## Enabling it

Flip `authenticate` to true on the same firewall key:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                checkbox: _device_bound_session
                authenticate: true
```

That is the only change: the binding store already carries the user identifier and the rotating
cookie token from the additive phase, so there is no data migration. See the
[configuration reference](configuration.md) for every option.

## Recommended layering

Split the job a long-lived session cookie usually does on its own into three clear layers:

1. **Interactive login** (password, WebAuthn, SSO) establishes who the user is.
2. A **short session cookie** covers the active browsing session.
3. **DBSC** is the device-bound replacement for remember-me: the long-lived credential that
   re-authenticates the user once the short session has expired.

If your app currently relies on a long session cookie (long session, no remember-me), you move to
this layering by shortening the session and letting DBSC carry the durable part. Your firewall and
user provider stay exactly as they are.

## Authentication level

A request authenticated from the device-bound cookie is granted `IS_AUTHENTICATED_REMEMBERED`,
never `IS_AUTHENTICATED_FULLY`, exactly like a remember-me re-authentication. The authenticator
produces a token that the trust resolver classifies as remembered.

This means your existing guards keep working unchanged: routes or actions protected by
`IS_AUTHENTICATED_FULLY` (changing a password, payment, administrative operations) still require a
fresh interactive login, even on a known device. Normal browsing protected by a role or by
`IS_AUTHENTICATED_REMEMBERED` is served from the device-bound cookie.

## Login-method agnostic

The authenticator does not care how the user logged in. At registration the binding records the
identifier of whoever was authenticated (password, WebAuthn, SSO, anything), and on a later
request the user is reloaded by identifier from the firewall's user provider. There is no coupling
to a particular login mechanism.

## What this protects

The exposure window of a stolen cookie is bounded by `max(session TTL, bound-cookie TTL)`, and
long-term persistence is eliminated: a stolen session cookie can no longer be turned into a
durable session, because re-authentication is device-bound.

It does not make the short session cookie itself unstealable for its own lifetime, so keep the
session short. Binding the session cookie directly, so that even it cannot be replayed, is a more
invasive change that is out of scope for this idiomatic setup.
