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

## 2. Registration endpoint

```
POST /dbsc/main/register
Secure-Session-Response: <JWS>
```

The browser sends the proof in the `Secure-Session-Response` header (the request body is empty).
It is a JWS with `typ: dbsc+jwt`, signed by the freshly generated device key, whose public part it
embeds (a `jwk` protected header, or a `key` claim). The `jti` claim carries the challenge from
the registration header.

The server verifies the signature against the embedded key (proof of possession), consumes the
challenge, records the binding (session identifier, public key, the authenticated user, a rotating
cookie token) and responds:

```
HTTP/1.1 200 OK
Set-Cookie: __Host-Http-dbsc_session=<token>; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax

{
  "session_identifier": "<opaque id>",
  "refresh_url": "/dbsc/main/refresh",
  "scope": { "origin": "https://example.com", "include_site": true, "scope_specification": [] },
  "credentials": [
    { "type": "cookie", "name": "__Host-Http-dbsc_session", "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax" }
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

The server answers with a fresh challenge:

```
HTTP/1.1 401 Unauthorized
Secure-Session-Challenge: "<value>"
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

An unknown session identifier or an invalid proof is answered with a fresh challenge (`401`)
rather than an error that would reveal whether the session exists.

## Access control

The two endpoints have opposite requirements: `refresh` must be publicly reachable (it
authenticates through the device proof, not the session), while `register` runs right after an
interactive login and must require authentication. The access control rules to declare are given
in [Additive mode](additive-mode.md#access-control-for-the-endpoints).

## Signature algorithms

Proofs are JWS signed with `ES256` or `RS256` by default. The accepted set is configurable and is
resolved from algorithms registered as services; see [Extending the bundle](extending.md#algorithms).
