# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-06

### Added

- `authorization` round-trip: `DeviceBoundSessionBadge::setAuthorization()` makes the bundle emit an `authorization` parameter in the `Secure-Session-Registration` header, bind it to the challenge, and verify the registration proof echoes it back unchanged (spec § 9.10). Lets you tie a registration to a value only your backend can vouch for.
- `Secure-Session-Skipped`: the bundle now logs (notice level) when a browser reports it skipped DBSC for a session (refresh endpoint unreachable, server error, or quota exceeded), to help spot a misbehaving endpoint.

### Changed

- The registration proof's embedded public key is now read from the `jwk` protected header first (the current draft), falling back to the legacy `key` payload claim for compatibility.

### Fixed

- Corrected the cookie-name guidance: the DBSC spec places no restriction on the bound cookie name, so `__Host-`/`__Secure-` prefixes are allowed (a `__Host-` name requires `secure`, `path=/` and no `domain`, which the defaults satisfy). The default stays the unprefixed `dbsc_session` for the broadest compatibility. The previous "browsers reject prefixed cookies" note (0.2.0) was inaccurate.

## [0.2.0] - 2026-06-05

### Added

- `session_lifetime`: lifetime of the device-bound credential (the binding), in seconds, independent of the short cookie. The refresh endpoint honours the binding until `createdAt + session_lifetime`, then terminates the session. This is the durable, remember-me-like part; the cookie stays short.
- `scope_exclude_paths`: paths kept out of the session scope (e.g. `/assets`, `/build`), so their requests never trigger a refresh. The browser fires one deferred refresh per concurrent in-scope request when the cookie expires; excluding static assets removes most of that churn.
- Automatic logout cleanup: a per-firewall `LogoutEvent` listener deletes the binding from the repository (so the cookie can no longer be refreshed) and clears the bound cookie, the same way `RememberMeListener` clears its persistent token and cookie. No application wiring required.

### Changed

- The default bound cookie name is now `dbsc_session` (was `__Host-Http-dbsc_session`). Browsers reject `__Host-`/`__Secure-` prefixed cookies as DBSC bound credentials, so the prefixed default silently failed registration.
- The session scope is now origin-scoped (`include_site: false`) with an explicit host `include` rule. The previous `include_site: true` with an empty specification was not maintained by Chrome on every origin.

### Fixed

- Refresh challenge handshake: the challenge is now returned with `403` and the required `id` structured-field parameter (`"<challenge>";id="<session>"`). The previous `401` is a `4xx` that makes the browser terminate the session, so the handshake never completed.
- The refresh endpoint now terminates the session with a `4xx` on an unknown or expired binding, instead of looping challenges.

## [0.1.0] - 2026-06-05

### Added

- Initial release. Device Bound Session Credentials wired per firewall via a `device_bound_session` authenticator factory.
- Additive mode (a device-bound cookie issued alongside the session) and replacement mode (`authenticate: true`, the bound cookie becomes the long-lived, remember-me-level credential).
- Registration and refresh endpoints, opt-in through a `DeviceBoundSessionBadge` on the login passport (always or from a checkbox parameter).
- A lazy device-bound authenticator that never overrides a token already established for the request (e.g. from the session), like remember-me.
- Pluggable persistent `SessionBindingRepository` and `ChallengeStore`, tagged JWS algorithm provider, and a web profiler panel.
