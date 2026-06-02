<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Challenge;

use Psr\Clock\ClockInterface;
use SpomkyLabs\DbscBundle\Exception\InvalidChallengeException;

/**
 * Issues and validates single-use challenges.
 */
final readonly class ChallengeManager implements ChallengeManagerInterface
{
    public function __construct(
        private ChallengeStore $store,
        private ClockInterface $clock,
        private int $ttl,
    ) {
    }

    public function issue(?string $sessionIdentifier = null): Challenge
    {
        $value = self::base64UrlEncode(random_bytes(32));
        $challenge = new Challenge($value, $this->clock->now()->getTimestamp() + $this->ttl, $sessionIdentifier);
        $this->store->save($challenge);

        return $challenge;
    }

    /**
     * Validates that the presented challenge value was issued, not expired and (when given)
     * bound to the expected session. Consumes it on success so it cannot be replayed.
     */
    public function consume(string $value, ?string $expectedSessionIdentifier = null): void
    {
        if ($value === '') {
            throw InvalidChallengeException::missing();
        }

        $challenge = $this->store->get($value);
        if ($challenge === null) {
            throw InvalidChallengeException::unknownOrExpired();
        }

        if ($expectedSessionIdentifier !== null
            && $challenge->sessionIdentifier !== null
            && ! hash_equals($challenge->sessionIdentifier, $expectedSessionIdentifier)
        ) {
            throw InvalidChallengeException::sessionMismatch();
        }

        $this->store->consume($value);
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
