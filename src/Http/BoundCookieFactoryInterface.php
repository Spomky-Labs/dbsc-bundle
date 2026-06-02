<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Http;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * Builds the short-lived device-bound cookie.
 */
interface BoundCookieFactoryInterface
{
    public function name(): string;

    public function create(string $value, int $now): Cookie;

    public function clear(): Cookie;
}
