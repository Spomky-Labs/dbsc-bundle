# Installation

## Requirements

- PHP 8.2 or higher
- Symfony 7.4 or 8.0 (security, http-foundation, http-kernel, routing, config)
- A firewall: the bundle relies on the Security component to know who the authenticated user is

The JWS verification relies on [web-token/jwt-library](https://github.com/web-token/jwt-framework),
which is pulled in automatically.

## Composer

```bash
composer require spomky-labs/dbsc-bundle
```

## Bundle registration

With Symfony Flex the bundle is registered automatically. Without Flex, add it to
`config/bundles.php`:

```php
return [
    // ...
    SpomkyLabs\DbscBundle\SpomkyLabsDbscBundle::class => ['all' => true],
];
```

## Routes

The bundle ships the registration and refresh routes. Import them once:

```yaml
# config/routes/dbsc.yaml
dbsc:
    resource: '@SpomkyLabsDbscBundle/config/routes.php'
```

The two routes resolve to the configured paths, `/dbsc/register` and `/dbsc/refresh` by default.

## Next steps

- Nothing else is required for [additive mode](additive-mode.md).
- Review the [configuration reference](configuration.md) to tune cookie attributes, the
  accepted algorithms or the challenge lifetime.
- Before production, replace the default in-memory stores with shared ones: see
  [Production storage](storage.md).
