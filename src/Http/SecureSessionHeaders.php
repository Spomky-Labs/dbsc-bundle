<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Http;

/**
 * Header names used by the DBSC protocol.
 *
 * The specification is still a draft; earlier revisions used the `Sec-Session-*` prefix.
 * This bundle follows the current `Secure-Session-*` / `Sec-Secure-Session-*` naming.
 *
 * @see https://w3c.github.io/webappsec-dbsc/
 */
final class SecureSessionHeaders
{
    /**
     * Response header emitted after a successful login to ask the browser to register a
     * device-bound key. Value example: `(ES256 RS256);challenge="...";path="/dbsc/register"`.
     */
    public const REGISTRATION = 'Secure-Session-Registration';

    /**
     * Request header carrying the DBSC session identifier on refresh.
     */
    public const SESSION_ID = 'Sec-Secure-Session-Id';

    /**
     * Response header carrying the challenge the browser must sign.
     */
    public const CHALLENGE = 'Secure-Session-Challenge';

    /**
     * Request header carrying the signed proof (a JWS) on registration and refresh.
     */
    public const RESPONSE = 'Secure-Session-Response';

    /**
     * Media type of the JWS body posted by the browser.
     */
    public const JWT_CONTENT_TYPE = 'application/jwt';

    /**
     * The `typ` header value of a DBSC proof JWS.
     */
    public const JWT_TYPE = 'dbsc+jwt';
}
