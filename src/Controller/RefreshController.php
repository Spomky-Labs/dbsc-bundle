<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Controller;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Exception\DbscException;
use SpomkyLabs\DbscBundle\Exception\SessionExpiredException;
use SpomkyLabs\DbscBundle\Exception\UnknownSessionException;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactoryInterface;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandlerInterface;
use SpomkyLabs\DbscBundle\Protocol\SessionConfigFactoryInterface;
use function sprintf;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * DBSC refresh endpoint. A request without a proof is answered with a challenge (403 +
 * `Secure-Session-Challenge` carrying the session id); the browser retries with a signed proof
 * in `Secure-Session-Response`, which is verified before a new bound cookie is issued. A dead or
 * expired session is answered with a terminating 4xx so the browser stops the session.
 */
final readonly class RefreshController
{
    public function __construct(
        private RefreshHandlerInterface $handler,
        private ChallengeManagerInterface $challengeManager,
        private BoundCookieFactoryInterface $cookieFactory,
        private ClockInterface $clock,
        private SessionConfigFactoryInterface $configFactory,
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $sessionIdentifier = (string) $request->headers->get(SecureSessionHeaders::SESSION_ID, '');
        if ($sessionIdentifier === '') {
            return new JsonResponse([
                'error' => 'missing_session_id',
            ], Response::HTTP_BAD_REQUEST);
        }

        $proof = $this->extractProof($request);
        if ($proof === '') {
            return $this->challenge($sessionIdentifier);
        }

        try {
            $issued = $this->handler->refresh(
                $sessionIdentifier,
                $proof,
                $request->getSchemeAndHttpHost(),
                $request->getSchemeAndHttpHost() . $request->getPathInfo(),
            );
        } catch (SessionExpiredException $e) {
            $this->logger->info('DBSC session expired on refresh.', [
                'exception' => $e,
            ]);

            return $this->terminate();
        } catch (UnknownSessionException $e) {
            $this->logger->info('DBSC session terminated on refresh.', [
                'exception' => $e,
            ]);

            return new JsonResponse([
                'error' => 'session_terminated',
            ], Response::HTTP_UNAUTHORIZED);
        } catch (DbscException $e) {
            $this->logger->warning('DBSC refresh rejected.', [
                'exception' => $e,
            ]);

            return $this->challenge($sessionIdentifier);
        }

        $response = new JsonResponse($issued->config);
        $response->headers->setCookie(
            $this->cookieFactory->create($issued->cookieValue, $this->clock->now()->getTimestamp()),
        );

        return $response;
    }

    private function extractProof(Request $request): string
    {
        $header = $request->headers->get(SecureSessionHeaders::RESPONSE);
        if ($header !== null && $header !== '') {
            return $header;
        }

        return trim($request->getContent());
    }

    /**
     * Gracefully ends a session whose durable lifetime has elapsed: a `200` carrying a
     * `continue: false` document and a cleared bound cookie, so the browser stops refreshing
     * without treating it as an error.
     */
    private function terminate(): Response
    {
        $response = new JsonResponse($this->configFactory->terminate());
        $response->headers->setCookie($this->cookieFactory->clear());

        return $response;
    }

    private function challenge(string $sessionIdentifier): Response
    {
        $challenge = $this->challengeManager->issue($sessionIdentifier);

        $response = new JsonResponse(null, Response::HTTP_FORBIDDEN);
        $response->headers->set(
            SecureSessionHeaders::CHALLENGE,
            sprintf('"%s";id="%s"', $challenge->value, $sessionIdentifier),
        );

        return $response;
    }
}
