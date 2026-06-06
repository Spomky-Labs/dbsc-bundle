# Adoption modes

The bundle is adopted in two steps: start safely, then graduate to the strongest protection with
the least possible impact. The binding store records the user identifier and the rotating cookie
token from the very first registration, so moving from one mode to the next needs no data
migration.

## [Additive mode](additive-mode.md)

A device-bound cookie is issued alongside your existing session, which stays authoritative.
Nothing about how requests are authenticated changes. Start here to observe real-world coverage
with zero risk.

## [Device-bound long-lived credential](replacement-mode.md)

DBSC takes over the long-lived re-authentication credential, the role of a remember-me cookie.
A request is then authenticated from the device-bound cookie, granted
`IS_AUTHENTICATED_REMEMBERED`. Enabling it is a single firewall option once additive mode is in
place.

Already using Symfony's remember-me? The [remember-me migration guide](remember-me-migration.md)
maps every option across and walks the two modes above as a gradual, fallback-safe migration.
