# Protocol and endpoints

The bundle implements the server side of DBSC. The browser performs the cryptography; the server
emits one header and answers two endpoints. Header names follow the current draft
(`Secure-Session-*` and `Sec-Secure-Session-*`); they are exposed as constants on
`SpomkyLabs\DbscBundle\Http\SecureSessionHeaders`.

## 1. Registration header (at login)

When a login passport carries a `DeviceBoundSessionBadge` (see
[Additive mode](additive-mode.md#opting-in-the-badge-and-its-conditions)), the bundle adds a header to the response:

```
Secure-Session-Registration: (ES256 RS256);challenge="<value>";path="/dbsc/main/register"
```

It lists the accepted algorithms, a single-use challenge and the registration path. The header is
emitted only when the badge is present, never on a device-bound re-authentication, so
registration is not re-triggered on every request. A browser that does not understand the header
ignores it.

If the `DeviceBoundSessionBadge` carries an application-defined `authorization` value, it is added
as an `authorization="<value>"` parameter:

```
Secure-Session-Registration: (ES256 RS256);challenge="<value>";path="/dbsc/main/register";authorization="<opaque>"
```

The browser must echo it back, unchanged, in the registration proof (an `authorization` claim). The
server checks it matches the value bound to the challenge and rejects the proof otherwise. Use it to
tie a registration to something only your backend can vouch for. Set it from your authenticator:

```php
$passport->addBadge((new DeviceBoundSessionBadge())->enable()->setAuthorization($value));
```

## 2. Registration endpoint

```
POST /dbsc/main/register
Secure-Session-Response: <JWS>
```

The browser sends the proof in the `Secure-Session-Response` header (the request body is empty).
It is a JWS with `typ: dbsc+jwt`, signed by the freshly generated device key, whose public part it
embeds in a `jwk` protected header (an older draft used a `key` payload claim, still accepted as a
fallback). The `jti` claim carries the challenge from the registration header.

The server verifies the signature against the embedded key (proof of possession), consumes the
challenge, records the binding (session identifier, public key, the authenticated user, a rotating
cookie token) and responds:

```
HTTP/1.1 200 OK
Set-Cookie: dbsc_session=<token>; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax

{
  "session_identifier": "<opaque id>",
  "refresh_url": "/dbsc/main/refresh",
  "scope": {
    "origin": "https://example.com",
    "include_site": false,
    "scope_specification": [
      { "type": "include", "domain": "example.com", "path": "/" }
    ]
  },
  "credentials": [
    { "type": "cookie", "name": "dbsc_session", "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax" }
  ]
}
```

## 3. Refresh endpoint

When the bound cookie nears expiry the browser calls the refresh endpoint. The exchange is two
steps: a challenge, then a signed proof.

First request, without a proof:

```
POST /dbsc/main/refresh
Sec-Secure-Session-Id: <session_identifier>
```

The server answers with a fresh challenge. The status is `403` (a `4xx` other than `403` would make
the browser terminate the session), and the challenge carries the session id in an `id` parameter:

```
HTTP/1.1 403 Forbidden
Secure-Session-Challenge: "<value>";id="<session_identifier>"
```

Second request, with the signed challenge:

```
POST /dbsc/main/refresh
Sec-Secure-Session-Id: <session_identifier>
Secure-Session-Response: <JWS>
```

The server verifies the signature against the stored public key, consumes the challenge, rotates
the cookie token and responds with the same session configuration document and a new
`Set-Cookie`. The browser then resumes the request it had deferred.

An invalid or stale proof is answered with a fresh challenge (`403`) so the browser retries. An
**unknown or expired** session, by contrast, is answered with a terminating `4xx` (`401`): the
browser ends the session and stops refreshing. Deleting a binding server-side (revocation, or the
automatic logout cleanup) therefore signs the device out, even though it still holds the device
key, because the server no longer has the public key to verify its proof.

## Browser-skipped sessions

When a supporting browser cannot run DBSC for a session (the refresh endpoint was unreachable,
returned a server error, or a quota was exceeded) it lets the request through without the bound
cookie and adds a `Secure-Session-Skipped` request header naming the reason and the session. The
spec does not require the server to react; the bundle logs the occurrence (notice level) so you can
spot a misbehaving or unreachable refresh endpoint. No application wiring is required.

## Access control

The two endpoints have opposite requirements: `refresh` must be publicly reachable (it
authenticates through the device proof, not the session), while `register` runs right after an
interactive login and must require authentication. The access control rules to declare are given
in [Additive mode](additive-mode.md#access-control-for-the-endpoints).

## Signature algorithms

Proofs are JWS signed with `ES256` or `RS256` by default. The accepted set is configurable and is
resolved from algorithms registered as services; see [Extending the bundle](extending.md#algorithms).
