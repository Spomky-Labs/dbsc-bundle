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
     */
    public function __construct(
        private string $refreshPath,
        private array $cookie,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function create(string $sessionIdentifier, string $origin): array
    {
        $host = parse_url($origin, PHP_URL_HOST);

        return [
            'session_identifier' => $sessionIdentifier,
            'refresh_url' => $this->refreshPath,
            'scope' => [
                'origin' => $origin,
                'include_site' => false,
                'scope_specification' => [
                    [
                        'type' => 'include',
                        'domain' => is_string($host) ? $host : '',
                        'path' => '/',
                    ],
                ],
            ],
            'credentials' => [
                [
                    'type' => 'cookie',
                    'name' => $this->cookie['name'],
                    'attributes' => $this->cookieAttributes(),
                ],
            ],
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
