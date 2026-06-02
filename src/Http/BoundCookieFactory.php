<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Http;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * Builds the short-lived device-bound cookie from the configured attributes.
 */
final readonly class BoundCookieFactory implements BoundCookieFactoryInterface
{
    /**
     * @param array{name: string, path: string, domain: ?string, secure: bool, http_only: bool, same_site: 'lax'|'strict'|'none', lifetime: int} $config
     */
    public function __construct(
        private array $config,
    ) {
    }

    public function name(): string
    {
        return $this->config['name'];
    }

    public function create(string $value, int $now): Cookie
    {
        return Cookie::create($this->config['name'])
            ->withValue($value)
            ->withExpires($now + $this->config['lifetime'])
            ->withPath($this->config['path'])
            ->withDomain($this->config['domain'])
            ->withSecure($this->config['secure'])
            ->withHttpOnly($this->config['http_only'])
            ->withSameSite($this->config['same_site']);
    }

    public function clear(): Cookie
    {
        return Cookie::create($this->config['name'])
            ->withValue('')
            ->withExpires(1)
            ->withPath($this->config['path'])
            ->withDomain($this->config['domain'])
            ->withSecure($this->config['secure'])
            ->withHttpOnly($this->config['http_only'])
            ->withSameSite($this->config['same_site']);
    }
}
