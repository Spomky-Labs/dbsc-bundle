<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\DataCollector;

use function is_string;
use function preg_match;
use Psr\Container\ContainerInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeStore;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use function substr;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollectorInterface;
use Throwable;

/**
 * Surfaces Device Bound Session Credentials state in the web profiler. Since configuration is
 * per firewall, the collector iterates every firewall that enables DBSC: for each it reports the
 * active configuration and, if its bound cookie is present on the request, the matching binding.
 * The registration header (emitted once per response) is reported globally.
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

    /**
     * @param array<string, array{register: string, refresh: string, cookie_name: string, algorithms: list<string>, challenge_ttl: int, authenticate: bool}> $firewalls
     * @param ContainerInterface                                                                                                                              $repositories    locator of per-firewall SessionBindingRepository, keyed by firewall name
     * @param ContainerInterface                                                                                                                              $challengeStores locator of per-firewall ChallengeStore, keyed by firewall name
     */
    public function __construct(
        private readonly array $firewalls,
        private readonly ContainerInterface $repositories,
        private readonly ContainerInterface $challengeStores,
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

        $firewalls = [];
        $anyCookiePresent = false;
        foreach ($this->firewalls as $name => $config) {
            $cookieName = $config['cookie_name'];
            $cookieValue = $request->cookies->get($cookieName);
            $present = is_string($cookieValue) && $cookieValue !== '';
            $anyCookiePresent = $anyCookiePresent || $present;

            $repository = $this->repositories->has($name) ? $this->repository($name) : null;
            $challengeStore = $this->challengeStores->has($name) ? $this->challengeStore($name) : null;

            $binding = $present && $repository !== null
                ? $repository->findByCookieToken((string) $cookieValue)
                : null;

            $firewalls[$name] = [
                'register_path' => $config['register'],
                'refresh_path' => $config['refresh'],
                'cookie_name' => $cookieName,
                'cookie_present' => $present,
                'cookie_preview' => $present ? substr((string) $cookieValue, 0, 8) . '…' : null,
                'algorithms' => $config['algorithms'],
                'challenge_ttl' => $config['challenge_ttl'],
                'authenticate' => $config['authenticate'],
                'binding_session_id' => $binding?->sessionIdentifier,
                'binding_user' => $binding?->userIdentifier,
                'binding_jwk' => $binding?->publicKeyJwk,
                'binding_repository' => $repository !== null ? $repository::class : null,
                'challenge_store' => $challengeStore !== null ? $challengeStore::class : null,
            ];
        }

        $this->data = [
            'registration_header' => $registration,
            'challenge' => $registration !== null ? $this->extractChallenge($registration) : null,
            'cookie_present' => $anyCookiePresent,
            'firewalls' => $firewalls,
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

    private function repository(string $firewall): SessionBindingRepository
    {
        /** @var SessionBindingRepository $repository */
        $repository = $this->repositories->get($firewall);

        return $repository;
    }

    private function challengeStore(string $firewall): ChallengeStore
    {
        /** @var ChallengeStore $store */
        $store = $this->challengeStores->get($firewall);

        return $store;
    }

    private function extractChallenge(string $registrationHeader): ?string
    {
        if (preg_match('/challenge="([^"]+)"/', $registrationHeader, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }
}
