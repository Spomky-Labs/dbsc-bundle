<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Protocol;

use InvalidArgumentException;

/**
 * The session provider a relying party asks the browser to share a device key with: the
 * provider's origin, the identifier of the provider session and the SHA-256 thumbprint of its
 * key. All three travel in the registration header (`provider_url`, `provider_session_id`,
 * `provider_key`); the browser reuses the provider's key only if both sites publish matching
 * `/.well-known/device-bound-sessions` documents.
 *
 * The values come from the provider out of band (e.g. claims of a federated login), typically
 * from the provider's {@see \SpomkyLabs\DbscBundle\Session\SessionBinding::keyThumbprint()}.
 */
final readonly class SessionProvider
{
    public function __construct(
        public string $url,
        public string $sessionId,
        public string $keyThumbprint,
    ) {
        if ($url === '' || $sessionId === '' || $keyThumbprint === '') {
            throw new InvalidArgumentException('A session provider needs a url, a session id and a key thumbprint.');
        }
    }
}
