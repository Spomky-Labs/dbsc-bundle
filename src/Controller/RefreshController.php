<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Controller;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SpomkyLabs\DbscBundle\Challenge\ChallengeManagerInterface;
use SpomkyLabs\DbscBundle\Exception\DbscException;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactoryInterface;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\RefreshHandlerInterface;
use function sprintf;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * DBSC refresh endpoint. A request without a proof is answered with a fresh challenge
 * (401 + `Secure-Session-Challenge`); the browser retries with a signed proof in
 * `Secure-Session-Response`, which is verified before a new bound cookie is issued.
 */
final readonly class RefreshController
{
    public function __construct(
        private RefreshHandlerInterface $handler,
        private ChallengeManagerInterface $challengeManager,
        private BoundCookieFactoryInterface $cookieFactory,
        private ClockInterface $clock,
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
            $issued = $this->handler->refresh($sessionIdentifier, $proof, $request->getSchemeAndHttpHost());
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

    private function challenge(string $sessionIdentifier): Response
    {
        $challenge = $this->challengeManager->issue($sessionIdentifier);

        $response = new JsonResponse(null, Response::HTTP_UNAUTHORIZED);
        $response->headers->set(SecureSessionHeaders::CHALLENGE, sprintf('"%s"', $challenge->value));

        return $response;
    }
}
