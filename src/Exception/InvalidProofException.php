<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Exception;

use function sprintf;

final class InvalidProofException extends DbscException
{
    public static function malformed(string $reason): self
    {
        return new self(sprintf('Malformed DBSC proof: %s.', $reason));
    }

    public static function unsupportedType(string $type): self
    {
        return new self(sprintf('Unexpected JWS "typ": "%s".', $type));
    }

    public static function unsupportedAlgorithm(string $algorithm): self
    {
        return new self(sprintf('Unsupported signature algorithm: "%s".', $algorithm));
    }

    public static function missingKey(): self
    {
        return new self('The registration proof does not embed a public key.');
    }

    public static function badSignature(): self
    {
        return new self('The proof signature could not be verified against the device key.');
    }
}
