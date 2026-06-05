# Extending the bundle

Since configuration is per firewall, most services are built per firewall from abstract templates
by the security factory; they are not global singletons you can alias once. There are three ways to
customise behaviour, depending on the piece.

## Per-firewall stores

The two persistence points are swapped through per-firewall configuration options, not a global
alias: `binding_repository` and `challenge_store`. Register your implementation as a service and
point the firewall at it. This is covered in [Production storage](storage.md).

| Interface | Default | Replaced via |
| --- | --- | --- |
| `Session\SessionBindingRepository` | per-firewall in-memory | `binding_repository` option |
| `Challenge\ChallengeStore` | per-firewall in-memory | `challenge_store` option |

## Per-firewall protocol services

These are configured through the firewall options rather than replaced: the accepted algorithms
(`algorithms`), the challenge lifetime (`challenge_ttl`) and the cookie attributes (`cookie`). Each
firewall gets its own instance of the algorithm provider, proof verifier, challenge manager, cookie
factory, session-config factory and the registration/refresh handlers, wired from those options.

| Service | Role |
| --- | --- |
| `Jwt\AlgorithmProvider` | Selects the accepted JWS algorithms |
| `Jwt\DeviceProofVerifier` | Verifies registration and refresh proofs |
| `Challenge\ChallengeManager` | Issues and consumes single-use challenges |
| `Protocol\RegistrationHandler` | Handles the registration step |
| `Protocol\RefreshHandler` | Handles the refresh step |
| `Protocol\SessionConfigFactory` | Builds the session configuration document |
| `Http\BoundCookieFactory` | Builds the short-lived bound cookie |

## Global services

A few stateless services are shared by every firewall and can be replaced with a global alias.
`TokenGeneratorInterface` (opaque identifiers and cookie tokens) is the main one:

```yaml
# config/services.yaml
services:
    App\Security\Dbsc\MyTokenGenerator: ~
    SpomkyLabs\DbscBundle\Protocol\TokenGeneratorInterface:
        alias: App\Security\Dbsc\MyTokenGenerator
```

## Algorithms

The accepted JWS algorithms are discovered dynamically: any service tagged
`dbsc.jose_algorithm` (the bundle auto-tags every `Jose\Component\Core\Algorithm` service) is
available, and the per-firewall `algorithms` configuration selects the subset that is actually accepted.

DBSC mandates `ES256` and `RS256`. To accept an additional algorithm, register it as a service so
it is tagged, then list it in the firewall configuration:

```yaml
# config/services.yaml
services:
    Jose\Component\Signature\Algorithm\ES384: ~
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            device_bound_session:
                algorithms: ['ES256', 'RS256', 'ES384']
```

Listing an algorithm that is not registered as a service is rejected, so the accepted set and the
available implementations cannot drift apart silently.

## Security token

In the device-bound credential mode the authenticator produces a
`SpomkyLabs\DbscBundle\Security\DeviceBoundSessionToken`, which extends Symfony's
`RememberMeToken` so the request is classified as `IS_AUTHENTICATED_REMEMBERED`. If you need a
different classification, provide your own authenticator; the rest of the bundle is unaffected.
