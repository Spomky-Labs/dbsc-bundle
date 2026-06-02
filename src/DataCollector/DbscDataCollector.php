<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\DataCollector;

use function is_string;
use function preg_match;
use SpomkyLabs\DbscBundle\Challenge\ChallengeStore;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Jwt\AlgorithmProviderInterface;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use function substr;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollectorInterface;
use Throwable;

/**
 * Surfaces Device Bound Session Credentials state in the web profiler: whether a registration
 * header was emitted on the response, whether the device-bound cookie is present on the request,
 * and the active configuration and stores.
 *
 * Implements DataCollectorInterface directly (rather than extending AbstractDataCollector, which
 * moved namespaces between Symfony 7.4 and 8.0) to stay portable across both; the profiler
 * template is declared on the `data_collector` service tag.
 */
final class DbscDataCollector implements DataCollectorInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $data = [];

    public function __construct(
        private readonly AlgorithmProviderInterface $algorithmProvider,
        private readonly SessionBindingRepository $bindings,
        private readonly ChallengeStore $challengeStore,
        private readonly string $cookieName,
        private readonly string $registrationPath,
        private readonly string $refreshPath,
        private readonly int $challengeTtl,
    ) {
    }

    /**
     * Only the collected data is serialized into the profiler; the injected services are not
     * (and may not be serializable).
     *
     * @return array<int, string>
     */
    public function __sleep(): array
    {
        return ['data'];
    }

    public function collect(Request $request, Response $response, ?Throwable $exception = null): void
    {
        $registration = $response->headers->get(SecureSessionHeaders::REGISTRATION);
        $cookieValue = $request->cookies->get($this->cookieName);

        $binding = is_string($cookieValue) && $cookieValue !== ''
            ? $this->bindings->findByCookieToken($cookieValue)
            : null;

        $this->data = [
            'registration_header' => $registration,
            'challenge' => $registration !== null ? $this->extractChallenge($registration) : null,
            'cookie_name' => $this->cookieName,
            'cookie_present' => $cookieValue !== null,
            'cookie_preview' => is_string($cookieValue) ? substr($cookieValue, 0, 8) . '…' : null,
            'binding_session_id' => $binding?->sessionIdentifier,
            'binding_user' => $binding?->userIdentifier,
            'binding_jwk' => $binding?->publicKeyJwk,
            'registration_path' => $this->registrationPath,
            'refresh_path' => $this->refreshPath,
            'challenge_ttl' => $this->challengeTtl,
            'algorithms' => $this->algorithmProvider->getAllowedNames(),
            'binding_repository' => $this->bindings::class,
            'challenge_store' => $this->challengeStore::class,
        ];
    }

    public function reset(): void
    {
        $this->data = [];
    }

    public function getRegistrationHeader(): ?string
    {
        $value = $this->data['registration_header'] ?? null;

        return is_string($value) ? $value : null;
    }

    public function isRegistrationRequested(): bool
    {
        return ($this->data['registration_header'] ?? null) !== null;
    }

    public function isCookiePresent(): bool
    {
        return (bool) ($this->data['cookie_present'] ?? false);
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function getName(): string
    {
        return 'dbsc';
    }

    private function extractChallenge(string $registrationHeader): ?string
    {
        if (preg_match('/challenge="([^"]+)"/', $registrationHeader, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }
}
