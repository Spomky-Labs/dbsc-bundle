<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use InvalidArgumentException;

/**
 * Builds the `/.well-known/device-bound-sessions` document from the `dbsc.federation`
 * configuration, enforcing the spec's shape: a session provider's document carries
 * `relying_origins` (and optionally `registering_origins`) and MUST NOT carry `provider_origin`;
 * a relying party's document carries `provider_origin` and MUST NOT carry `relying_origins`. A
 * site is therefore one or the other, never both.
 */
final class WellKnownDocumentFactory
{
    /**
     * @param list<string> $relyingOrigins
     * @param list<string> $registeringOrigins
     *
     * @return array<string, mixed>|null null when federation is not configured (no document to serve)
     */
    public static function create(?string $providerOrigin, array $relyingOrigins, array $registeringOrigins): ?array
    {
        $isRelyingParty = $providerOrigin !== null;
        $isProvider = $relyingOrigins !== [] || $registeringOrigins !== [];

        if ($isRelyingParty && $isProvider) {
            throw new InvalidArgumentException(
                'dbsc.federation: a site is either a relying party (provider_origin) or a session provider (relying_origins / registering_origins), not both.'
            );
        }

        if ($isRelyingParty) {
            return [
                'provider_origin' => $providerOrigin,
            ];
        }

        if (! $isProvider) {
            return null;
        }

        $document = [
            'relying_origins' => $relyingOrigins,
        ];
        if ($registeringOrigins !== []) {
            $document['registering_origins'] = $registeringOrigins;
        }

        return $document;
    }
}
