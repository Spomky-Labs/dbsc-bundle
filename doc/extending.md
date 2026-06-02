# Extending the bundle

Every service in the bundle is defined behind an interface and wired by an alias, so you can
replace any piece by aliasing its interface to your own implementation. The persistence
interfaces are covered in [Production storage](storage.md); this page lists the rest.

## Interfaces

| Interface | Default | Role |
| --- | --- | --- |
| `Session\SessionBindingRepository` | in-memory | Stores session, key, user, cookie token |
| `Challenge\ChallengeStore` | in-memory | Stores issued challenges |
| `Challenge\ChallengeManagerInterface` | `ChallengeManager` | Issues and consumes single-use challenges |
| `Jwt\AlgorithmProviderInterface` | `AlgorithmProvider` | Selects the accepted JWS algorithms |
| `Jwt\DeviceProofVerifierInterface` | `DeviceProofVerifier` | Verifies registration and refresh proofs |
| `Protocol\RegistrationHandlerInterface` | `RegistrationHandler` | Handles the registration step |
| `Protocol\RefreshHandlerInterface` | `RefreshHandler` | Handles the refresh step |
| `Protocol\SessionConfigFactoryInterface` | `SessionConfigFactory` | Builds the session configuration document |
| `Protocol\TokenGeneratorInterface` | `TokenGenerator` | Generates opaque identifiers and cookie tokens |
| `Http\BoundCookieFactoryInterface` | `BoundCookieFactory` | Builds the short-lived bound cookie |

To replace one, register your service and alias the interface to it:

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
available, and the `dbsc.algorithms` configuration selects the subset that is actually accepted.

DBSC mandates `ES256` and `RS256`. To accept an additional algorithm, register it as a service so
it is tagged, then list it in the configuration:

```yaml
# config/services.yaml
services:
    Jose\Component\Signature\Algorithm\ES384: ~
```

```yaml
# config/packages/dbsc.yaml
dbsc:
    algorithms: ['ES256', 'RS256', 'ES384']
```

Listing an algorithm that is not registered as a service is rejected, so the accepted set and the
available implementations cannot drift apart silently.

## Security token

In the device-bound credential mode the authenticator produces a
`SpomkyLabs\DbscBundle\Security\DeviceBoundSessionToken`, which extends Symfony's
`RememberMeToken` so the request is classified as `IS_AUTHENTICATED_REMEMBERED`. If you need a
different classification, provide your own authenticator; the rest of the bundle is unaffected.
