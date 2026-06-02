# Concepts and security model

## The problem

Session and remember-me cookies are bearer tokens: whoever holds one is treated as the
authenticated user. Malware and infostealers exfiltrate cookies straight from the browser
profile, and a stolen cookie replayed from another machine grants the attacker the victim's
session. Phishing-resistant login (such as WebAuthn) does not help here, because the theft
happens after login.

## The idea

DBSC introduces a key pair tied to the device. The private key is generated and held by the
browser inside secure hardware (a Trusted Platform Module when available) and never leaves it.
The session is bound to that key. To keep the session alive the browser must periodically prove
possession of the private key by signing a server challenge. A copied cookie is useless on
another device, because that device does not hold the private key and cannot produce the proof.

## Protocol flow

1. **Login.** Your application authenticates the user as usual. The bundle adds a
   `Secure-Session-Registration` header to the response, announcing the accepted signature
   algorithms, a challenge and the registration endpoint.
2. **Registration.** A supporting browser generates a device key pair and posts a signed JWS
   (a proof of possession that embeds the public key) to the registration endpoint. The server
   verifies the signature, records the binding (session, public key, user, rotating cookie
   token) and returns a session configuration document together with a short-lived bound cookie.
3. **Refresh.** When the bound cookie nears expiry the browser calls the refresh endpoint. The
   server answers with a fresh challenge, the browser signs it with the device key, and the
   server verifies the signature against the stored public key before issuing the next
   short-lived cookie. The user sees nothing; the browser defers the original request until the
   refresh completes.

## What it protects

DBSC removes the long-term value of a stolen cookie. The exposure of a copied cookie is bounded
by the lifetime of the short bound cookie, after which a refresh is required and fails on a
device that does not hold the key. There is no lasting account takeover from cookie theft alone.

DBSC does not replace login security, does not encrypt traffic and does not protect a cookie
during the very short window before its first refresh. It is one layer among others (HTTPS,
HttpOnly, SameSite, strong login).

## Browser support and graceful degradation

DBSC is driven by the browser and is, at the time of writing, mostly available in desktop
Chrome behind an origin trial. A browser that does not understand the
`Secure-Session-Registration` header simply ignores it, and the application keeps working
exactly as before. Adopting the bundle therefore carries no regression risk for unsupported
clients.

## Scope

DBSC protects cookie-based, stateful sessions. It is not relevant to stateless APIs
authenticated by bearer tokens, which do not rely on cookies. See [Adoption modes](modes.md)
for how the bundle fits a session-cookie application.
