<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Exception;

final class InvalidChallengeException extends DbscException
{
    public static function missing(): self
    {
        return new self('No challenge was presented.');
    }

    public static function unknownOrExpired(): self
    {
        return new self('The presented challenge is unknown or has expired.');
    }

    public static function sessionMismatch(): self
    {
        return new self('The challenge was not issued for this session.');
    }
}
