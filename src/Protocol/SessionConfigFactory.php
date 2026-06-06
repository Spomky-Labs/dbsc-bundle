<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use function is_string;
use const PHP_URL_HOST;

/**
 * Builds the DBSC session configuration document returned from the registration and
 * refresh endpoints.
 *
 * @see https://w3c.github.io/webappsec-dbsc/#session-config
 */
final readonly class SessionConfigFactory implements SessionConfigFactoryInterface
{
    /**
     * @param array{name: string, path: string, domain: ?string, secure: bool, http_only: bool, same_site: string, lifetime: int} $cookie
     * @param list<string> $excludePaths paths kept out of the session scope (e.g. static assets) so
     *                                    their requests never trigger a refresh
     * @param bool         $includeSite  true emits a site-scoped session (`include_site: true`), false
     *                                    keeps it origin-scoped
     * @param list<string> $allowedRefreshInitiators origins allowed to initiate a refresh; emitted as
     *                                                `allowed_refresh_initiators` only when non-empty
     */
    public function __construct(
        private string $refreshPath,
        private array $cookie,
        private array $excludePaths = [],
        private bool $includeSite = false,
        private array $allowedRefreshInitiators = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function create(string $sessionIdentifier, string $origin): array
    {
        $parsedHost = parse_url($origin, PHP_URL_HOST);
        $host = is_string($parsedHost) ? $parsedHost : '';

        $scopeSpecification = [
            [
                'type' => 'include',
                'domain' => $host,
                'path' => '/',
            ],
        ];
        foreach ($this->excludePaths as $path) {
            $scopeSpecification[] = [
                'type' => 'exclude',
                'domain' => $host,
                'path' => $path,
            ];
        }

        $config = [
            'session_identifier' => $sessionIdentifier,
            'refresh_url' => $this->refreshPath,
            'scope' => [
                'origin' => $origin,
                'include_site' => $this->includeSite,
                'scope_specification' => $scopeSpecification,
            ],
            'credentials' => [
                [
                    'type' => 'cookie',
                    'name' => $this->cookie['name'],
                    'attributes' => $this->cookieAttributes(),
                ],
            ],
        ];

        if ($this->allowedRefreshInitiators !== []) {
            $config['allowed_refresh_initiators'] = $this->allowedRefreshInitiators;
        }

        return $config;
    }

    /**
     * @return array<string, mixed>
     */
    public function terminate(): array
    {
        return [
            'continue' => false,
        ];
    }

    private function cookieAttributes(): string
    {
        $parts = ['Path=' . $this->cookie['path']];
        if ($this->cookie['domain'] !== null) {
            $parts[] = 'Domain=' . $this->cookie['domain'];
        }
        if ($this->cookie['secure'] === true) {
            $parts[] = 'Secure';
        }
        if ($this->cookie['http_only'] === true) {
            $parts[] = 'HttpOnly';
        }
        $parts[] = 'SameSite=' . ucfirst($this->cookie['same_site']);

        return implode('; ', $parts);
    }
}
