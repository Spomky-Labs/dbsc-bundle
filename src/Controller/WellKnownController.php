<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Controller;

use const JSON_UNESCAPED_SLASHES;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Serves `/.well-known/device-bound-sessions`, the document a browser fetches (without
 * credentials) from both sites before letting a relying party share a session provider's device
 * key: the provider lists the `relying_origins` it allows, the relying party names its
 * `provider_origin`. The document is built once from the `dbsc.federation` configuration.
 */
final readonly class WellKnownController
{
    /**
     * @param array<string, mixed> $document
     */
    public function __construct(
        private array $document,
    ) {
    }

    public function __invoke(): Response
    {
        $response = new JsonResponse();
        $response->setEncodingOptions(JSON_UNESCAPED_SLASHES);

        return $response->setData($this->document);
    }
}
