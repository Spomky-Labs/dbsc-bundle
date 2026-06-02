# DBSC Bundle documentation

Device Bound Session Credentials (DBSC) for Symfony. These pages cover the concepts, the
configuration and the two ways to adopt the bundle.

## Contents

1. [Concepts and security model](concepts.md)
   What DBSC is, how the protocol flows, what it protects, and the state of browser support.
2. [Installation](installation.md)
   Requirements, Composer, and bundle registration.
3. [Configuration reference](configuration.md)
   Every option under the `dbsc` key, with defaults.
4. [Adoption modes](modes.md)
   How to choose between the two modes below.
   - [Additive mode](additive-mode.md): the device-bound cookie sits alongside your session.
   - [Device-bound long-lived credential](replacement-mode.md): the remember-me replacement.
5. [Protocol and endpoints](protocol.md)
   The registration header, the two endpoints, the headers and the JSON payloads.
6. [Production storage](storage.md)
   Replacing the in-memory stores with shared, persistent ones for multi-node deployments.
7. [Extending the bundle](extending.md)
   The interfaces you can implement to customise behaviour.

## In one paragraph

DBSC binds an authenticated browser session to a private key stored in the device hardware
(a TPM when available). The browser proves possession of that key when it registers, and again
each time the short-lived cookie is refreshed. An attacker who copies the cookie to another
machine cannot reproduce the proof, so the stolen cookie stops working at the next refresh. The
browser performs all the cryptography; the server only emits a header at login and answers two
endpoints, both provided by this bundle.
