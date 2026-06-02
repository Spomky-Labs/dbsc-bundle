<?php

declare(strict_types=1);

namespace SpomkyLabs\DbscBundle\Jwt;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use SpomkyLabs\DbscBundle\Exception\InvalidProofException;

/**
 * Builds the JWS {@see AlgorithmManager} from the JWS algorithms registered as services
 * (tagged `dbsc.jose_algorithm`), restricted to the configured allow-list.
 *
 * Algorithms are discovered dynamically: any tagged {@see Algorithm} service becomes
 * available, and the `dbsc.algorithms` configuration selects which ones are accepted.
 * DBSC mandates ES256 and RS256.
 */
final class AlgorithmProvider implements AlgorithmProviderInterface
{
    /**
     * @var array<string, Algorithm>
     */
    private array $available;

    /**
     * @param iterable<Algorithm> $algorithms the tagged JWS algorithm services
     * @param list<string>        $allowed    the configured, accepted algorithm names
     */
    public function __construct(
        iterable $algorithms,
        private readonly array $allowed,
    ) {
        $this->available = [];
        foreach ($algorithms as $algorithm) {
            $this->available[$algorithm->name()] = $algorithm;
        }
    }

    public function getManager(): AlgorithmManager
    {
        $selected = [];
        foreach ($this->allowed as $name) {
            if (! isset($this->available[$name])) {
                throw InvalidProofException::unsupportedAlgorithm($name);
            }
            $selected[] = $this->available[$name];
        }

        return new AlgorithmManager($selected);
    }

    /**
     * @return list<string>
     */
    public function getAllowedNames(): array
    {
        return array_values($this->allowed);
    }
}
