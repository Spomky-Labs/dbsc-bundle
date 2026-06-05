<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Exception;

use function sprintf;

final class SessionExpiredException extends DbscException
{
    public static function forIdentifier(string $sessionIdentifier): self
    {
        return new self(sprintf('Device-bound session "%s" has reached its lifetime.', $sessionIdentifier));
    }
}
