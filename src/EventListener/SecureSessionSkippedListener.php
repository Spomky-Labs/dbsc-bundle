<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\EventListener;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SpomkyLabs\DbscBundle\Http\SecureSessionHeaders;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Surfaces the `Secure-Session-Skipped` request header for observability.
 *
 * A supporting browser sends this header when it could not run DBSC for a session (the refresh
 * endpoint was unreachable, returned a server error, or a quota was exceeded) and is letting the
 * request through without the bound cookie. The spec does not require the server to react; the
 * bundle simply logs it so operators can spot a misbehaving or unreachable refresh endpoint.
 */
final readonly class SecureSessionSkippedListener
{
    public function __construct(
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $value = $event->getRequest()
            ->headers->get(SecureSessionHeaders::SKIPPED);
        if ($value === null || $value === '') {
            return;
        }

        $this->logger->notice('The browser skipped DBSC for a session.', [
            'secure_session_skipped' => $value,
        ]);
    }
}
