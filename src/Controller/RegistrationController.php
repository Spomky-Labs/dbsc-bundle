<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Controller;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SpomkyLabs\DbscBundle\Exception\DbscException;
use SpomkyLabs\DbscBundle\Http\BoundCookieFactoryInterface;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use SpomkyLabs\DbscBundle\Protocol\RegistrationHandlerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * DBSC registration endpoint (StartSession). The browser sends the registration proof (a JWS
 * embedding the device public key) in the `Secure-Session-Response` header, while still
 * carrying the authenticated session cookie.
 */
final readonly class RegistrationController
{
    public function __construct(
        private RegistrationHandlerInterface $handler,
        private BoundCookieFactoryInterface $cookieFactory,
        private TokenStorageInterface $tokenStorage,
        private ClockInterface $clock,
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $userIdentifier = $this->tokenStorage->getToken()?->getUserIdentifier();

        try {
            $issued = $this->handler->register(
                $this->extractProof($request),
                $userIdentifier,
                $request->getSchemeAndHttpHost(),
                $request->getSchemeAndHttpHost() . $request->getPathInfo(),
            );
        } catch (DbscException $e) {
            $this->logger->warning('DBSC registration rejected.', [
                'exception' => $e,
            ]);

            return new JsonResponse([
                'error' => 'registration_failed',
            ], Response::HTTP_BAD_REQUEST);
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
}
