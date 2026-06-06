<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\DataCollector;

use function array_filter;
use function array_values;
use function base64_decode;
use function explode;
use function is_array;
use function is_string;
use function json_decode;
use function preg_match;
use Psr\Container\ContainerInterface;
use SpomkyLabs\DbscBundle\Challenge\ChallengeStore;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Session\SessionBindingRepository;
use function strtr;
use function substr;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollectorInterface;
use Throwable;

/**
 * Surfaces Device Bound Session Credentials state in the web profiler. Since configuration is
 * per firewall, the collector iterates every firewall that enables DBSC: for each it reports the
 * full active configuration and, if its bound cookie is present on the request, the matching
 * binding. The registration header (emitted once per response after login) is reported globally.
 *
 * When the current request is itself a registration or refresh request — its path matches a
 * firewall's register/refresh endpoint — the collector additionally records what happened on that
 * endpoint (the submitted proof, the issued challenge, the rotated/cleared bound cookie and the
 * outcome), so the profile of an otherwise headless fetch() carries the DBSC exchange. The proof
 * JWS is decoded for display only; its signature is not verified here.
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
     * @param array<string, array<string, mixed>> $firewalls       per-firewall DBSC configuration, keyed by firewall name
     * @param ContainerInterface                   $repositories    locator of per-firewall SessionBindingRepository, keyed by firewall name
     * @param ContainerInterface                   $challengeStores locator of per-firewall ChallengeStore, keyed by firewall name
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
            $cookieName = $this->cookieName($config);
            $cookieValue = $request->cookies->get($cookieName);
            $present = is_string($cookieValue) && $cookieValue !== '';
            $anyCookiePresent = $anyCookiePresent || $present;

            $repository = $this->repositories->has($name) ? $this->repository($name) : null;
            $challengeStore = $this->challengeStores->has($name) ? $this->challengeStore($name) : null;

            $binding = $present && $repository !== null
                ? $repository->findByCookieToken((string) $cookieValue)
                : null;

            $firewalls[$name] = [
                'register_path' => $config['register'] ?? null,
                'refresh_path' => $config['refresh'] ?? null,
                'cookie_name' => $cookieName,
                'cookie' => $config['cookie'] ?? [
                    'name' => $cookieName,
                ],
                'cookie_present' => $present,
                'cookie_preview' => $present ? $this->preview((string) $cookieValue) : null,
                'algorithms' => $config['algorithms'] ?? [],
                'challenge_ttl' => $config['challenge_ttl'] ?? null,
                'session_lifetime' => $config['session_lifetime'] ?? null,
                'authenticate' => (bool) ($config['authenticate'] ?? false),
                'always' => (bool) ($config['always'] ?? false),
                'checkbox' => $config['checkbox'] ?? null,
                'include_site' => (bool) ($config['include_site'] ?? false),
                'scope_exclude_paths' => $config['scope_exclude_paths'] ?? [],
                'allowed_refresh_initiators' => $config['allowed_refresh_initiators'] ?? [],
                'binding_repository_service' => $config['binding_repository_service'] ?? null,
                'challenge_store_service' => $config['challenge_store_service'] ?? null,
                'binding_session_id' => $binding?->sessionIdentifier,
                'binding_user' => $binding?->userIdentifier,
                'binding_jwk' => $binding?->publicKeyJwk,
                'binding_repository' => $repository !== null ? $repository::class : null,
                'challenge_store' => $challengeStore !== null ? $challengeStore::class : null,
            ];
        }

        $this->data = [
            'registration_header' => $registration,
            'registration' => $registration !== null ? $this->parseRegistration($registration) : null,
            'challenge' => $registration !== null ? $this->extractChallenge($registration) : null,
            'skipped' => $request->headers->get(SecureSessionHeaders::SKIPPED),
            'cookie_present' => $anyCookiePresent,
            'endpoint' => $this->collectEndpoint($request, $response),
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
     * Endpoint activity recorded when the current request hit a register/refresh endpoint.
     *
     * @return array<string, mixed>|null
     */
    public function getEndpoint(): ?array
    {
        /** @var array<string, mixed>|null $endpoint */
        $endpoint = $this->data['endpoint'] ?? null;

        return $endpoint;
    }

    /**
     * The registration header parsed into its components, or null when no registration was offered.
     * Defaults gracefully so profiles collected before this key existed stay viewable.
     *
     * @return array{algorithms: list<string>, challenge: string|null, path: string|null, authorization: string|null}|null
     */
    public function getRegistration(): ?array
    {
        /** @var array{algorithms: list<string>, challenge: string|null, path: string|null, authorization: string|null}|null $registration */
        $registration = $this->data['registration'] ?? null;

        return $registration;
    }

    public function getSkipped(): ?string
    {
        $value = $this->data['skipped'] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * Per-firewall data, each entry backfilled with defaults so the template renders profiles
     * collected before the richer configuration keys existed.
     *
     * @return array<string, array<string, mixed>>
     */
    public function getFirewalls(): array
    {
        /** @var array<string, array<string, mixed>> $firewalls */
        $firewalls = $this->data['firewalls'] ?? [];

        $defaults = [
            'register_path' => null,
            'refresh_path' => null,
            'cookie_name' => 'dbsc_session',
            'cookie' => [],
            'cookie_present' => false,
            'cookie_preview' => null,
            'algorithms' => [],
            'challenge_ttl' => null,
            'session_lifetime' => null,
            'authenticate' => false,
            'always' => false,
            'checkbox' => null,
            'include_site' => false,
            'scope_exclude_paths' => [],
            'allowed_refresh_initiators' => [],
            'binding_repository_service' => null,
            'challenge_store_service' => null,
            'binding_session_id' => null,
            'binding_user' => null,
            'binding_jwk' => null,
            'binding_repository' => null,
            'challenge_store' => null,
        ];

        foreach ($firewalls as $name => $firewall) {
            $firewalls[$name] = $firewall + $defaults;
        }

        return $firewalls;
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

    /**
     * @param array<string, mixed> $config
     */
    private function cookieName(array $config): string
    {
        $cookie = $config['cookie'] ?? null;
        if (is_array($cookie) && is_string($cookie['name'] ?? null)) {
            return $cookie['name'];
        }

        $name = $config['cookie_name'] ?? null;

        return is_string($name) ? $name : 'dbsc_session';
    }

    /**
     * Detects whether the current request is a registration or refresh request (its path matches a
     * firewall endpoint) and, if so, records what the exchange produced.
     *
     * @return array<string, mixed>|null
     */
    private function collectEndpoint(Request $request, Response $response): ?array
    {
        $path = $request->getPathInfo();
        foreach ($this->firewalls as $name => $config) {
            if (($config['register'] ?? null) === $path) {
                return $this->collectRegister((string) $name, $config, $request, $response);
            }
            if (($config['refresh'] ?? null) === $path) {
                return $this->collectRefresh((string) $name, $config, $request, $response);
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function collectRegister(string $name, array $config, Request $request, Response $response): array
    {
        $proof = $this->proof($request);
        $status = $response->getStatusCode();
        $cookie = $this->boundCookie($response, $this->cookieName($config));

        return [
            'firewall' => $name,
            'type' => 'register',
            'path' => $config['register'] ?? $request->getPathInfo(),
            'status' => $status,
            'had_proof' => $proof !== null,
            'proof_header' => $proof !== null ? $this->decodeSegment($proof, 0) : null,
            'proof_payload' => $proof !== null ? $this->decodeSegment($proof, 1) : null,
            'outcome' => match (true) {
                $status === Response::HTTP_OK => 'registered',
                $status === Response::HTTP_BAD_REQUEST => 'registration_failed',
                default => 'error',
            },
            'session_config' => $status === Response::HTTP_OK ? $this->jsonBody($response) : null,
            'error' => $status >= 400 ? $this->errorCode($response) : null,
            'cookie_set' => $cookie !== null && $cookie->getValue() !== null && $cookie->getValue() !== '',
            'cookie_cleared' => false,
            'cookie_preview' => $cookie !== null ? $this->preview((string) $cookie->getValue()) : null,
        ];
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function collectRefresh(string $name, array $config, Request $request, Response $response): array
    {
        $proof = $this->proof($request);
        $sessionId = $request->headers->get(SecureSessionHeaders::SESSION_ID);
        $status = $response->getStatusCode();
        $challenge = $response->headers->get(SecureSessionHeaders::CHALLENGE);
        $body = $this->jsonBody($response);
        $continue = is_array($body) ? ($body['continue'] ?? null) : null;
        $cookie = $this->boundCookie($response, $this->cookieName($config));
        $cleared = $cookie !== null && ($cookie->getValue() === null || $cookie->getValue() === '');

        return [
            'firewall' => $name,
            'type' => 'refresh',
            'path' => $config['refresh'] ?? $request->getPathInfo(),
            'status' => $status,
            'session_id' => $sessionId !== '' ? $sessionId : null,
            'had_proof' => $proof !== null,
            'phase' => $proof !== null ? 'proof_submission' : 'challenge_request',
            'proof_header' => $proof !== null ? $this->decodeSegment($proof, 0) : null,
            'proof_payload' => $proof !== null ? $this->decodeSegment($proof, 1) : null,
            'challenge' => $challenge,
            'outcome' => match (true) {
                $status === Response::HTTP_BAD_REQUEST => 'missing_session_id',
                $status === Response::HTTP_UNAUTHORIZED => 'session_terminated',
                $status === Response::HTTP_FORBIDDEN => 'challenge_issued',
                $status === Response::HTTP_OK && $continue === false => 'terminated',
                $status === Response::HTTP_OK => 'refreshed',
                default => 'error',
            },
            'session_config' => $status === Response::HTTP_OK ? $body : null,
            'error' => $status >= 400 ? $this->errorCode($response) : null,
            'cookie_set' => $cookie !== null && ! $cleared,
            'cookie_cleared' => $cleared,
            'cookie_preview' => $cookie !== null && ! $cleared ? $this->preview((string) $cookie->getValue()) : null,
        ];
    }

    private function proof(Request $request): ?string
    {
        $header = $request->headers->get(SecureSessionHeaders::RESPONSE);

        return is_string($header) && $header !== '' ? $header : null;
    }

    private function boundCookie(Response $response, string $cookieName): ?Cookie
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === $cookieName) {
                return $cookie;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function jsonBody(Response $response): ?array
    {
        $content = $response->getContent();
        if (! is_string($content) || $content === '') {
            return null;
        }

        $data = json_decode($content, true);
        if (! is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    private function errorCode(Response $response): ?string
    {
        $body = $this->jsonBody($response);
        $error = is_array($body) ? ($body['error'] ?? null) : null;

        return is_string($error) ? $error : null;
    }

    /**
     * Decodes a single JWS segment (0 = header, 1 = payload) for display. The signature is never
     * verified here; this is a best-effort, unauthenticated view of the submitted proof.
     *
     * @return array<string, mixed>|null
     */
    private function decodeSegment(string $jws, int $index): ?array
    {
        $parts = explode('.', $jws);
        if (! isset($parts[$index]) || $parts[$index] === '') {
            return null;
        }

        $decoded = base64_decode(strtr($parts[$index], '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        $data = json_decode($decoded, true);
        if (! is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Parses the registration header into its components for display.
     *
     * @return array{algorithms: list<string>, challenge: string|null, path: string|null, authorization: string|null}
     */
    private function parseRegistration(string $header): array
    {
        $algorithms = [];
        if (preg_match('/^\(([^)]*)\)/', $header, $matches) === 1) {
            $algorithms = array_values(
                array_filter(explode(' ', trim($matches[1])), static fn (string $a): bool => $a !== '')
            );
        }

        return [
            'algorithms' => $algorithms,
            'challenge' => $this->extractAttribute($header, 'challenge'),
            'path' => $this->extractAttribute($header, 'path'),
            'authorization' => $this->extractAttribute($header, 'authorization'),
        ];
    }

    private function extractChallenge(string $registrationHeader): ?string
    {
        return $this->extractAttribute($registrationHeader, 'challenge');
    }

    private function extractAttribute(string $header, string $attribute): ?string
    {
        if (preg_match('/' . $attribute . '="([^"]+)"/', $header, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }

    private function preview(string $value): string
    {
        return substr($value, 0, 8) . '…';
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
}
