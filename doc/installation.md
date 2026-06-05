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

The bundle generates the registration and refresh routes — one pair per firewall that enables
DBSC. Import the loader once:

```yaml
# config/routes/dbsc.yaml
dbsc:
    resource: '@SpomkyLabsDbscBundle/config/routes.php'
```

For a firewall named `main` this yields `/dbsc/main/register` and `/dbsc/main/refresh` by default;
override the paths per firewall with the `register` / `refresh` options. The routes appear only
once a firewall opts in (see below), so importing the resource on a project with no DBSC firewall
is harmless.

## Next steps

- Enable DBSC on a firewall with `device_bound_session: true`. Nothing else is required for
  [additive mode](additive-mode.md).
- Review the [configuration reference](configuration.md) to tune cookie attributes, the
  accepted algorithms or the challenge lifetime.
- Before production, replace the default in-memory stores with shared ones: see
  [Production storage](storage.md).
