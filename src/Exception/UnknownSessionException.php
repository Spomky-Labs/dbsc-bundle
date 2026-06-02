<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Exception;

use function sprintf;

final class UnknownSessionException extends DbscException
{
    public static function forIdentifier(string $sessionIdentifier): self
    {
        return new self(sprintf('No device binding for session "%s".', $sessionIdentifier));
    }
}
