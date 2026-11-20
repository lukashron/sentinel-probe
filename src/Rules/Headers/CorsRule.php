<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'headers.cors',
    name: 'CORS',
    category: 'Headers',
    description: 'Sends requests with a foreign Origin header (a made-up domain and "null") and checks whether the server allows it in Access-Control-Allow-Origin. Reflecting any origin together with Access-Control-Allow-Credentials lets any website read responses with the visitor\'s cookies.',
    remediation: <<<'TXT'
        Allow only a fixed list of trusted origins and compare the Origin header against it exactly.
        Never reflect the Origin header blindly and never allow the "null" origin.
        Send Access-Control-Allow-Credentials: true only for trusted origins that need it.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
        'https://portswigger.net/web-security/cors',
    ],
)]
final readonly class CorsRule implements RuleInterface
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $foreignOrigin = sprintf('https://sentinel-probe-%s.example', bin2hex(random_bytes(4)));

        try {
            // both requests run concurrently, HttpResponse reads them afterwards
            $requests = [
                $foreignOrigin => $this->httpClient->request('GET', $response->url(), [
                    'timeout' => 10,
                    'headers' => ['Origin' => $foreignOrigin],
                ]),
                'null' => $this->httpClient->request('GET', $response->url(), [
                    'timeout' => 10,
                    'headers' => ['Origin' => 'null'],
                ]),
            ];

            $probes = array_map(static fn($request) => new HttpResponse($request), $requests);
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'CORS',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        $failures = [];
        $warnings = [];

        foreach ($probes as $origin => $probe) {
            $allowed = $probe->header('access-control-allow-origin');
            $credentials = strtolower($probe->header('access-control-allow-credentials') ?? '') === 'true';

            if ($allowed !== (string)$origin) {
                continue;
            }

            if ($credentials) {
                $failures[] = sprintf('Origin "%s" is allowed with credentials, any site can read responses with the visitor\'s cookies', $origin);
            } else {
                $warnings[] = sprintf('Origin "%s" is allowed, the server reflects any origin', $origin);
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'CORS',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'CORS',
                message: implode('; ', $warnings),
            );
        }

        if ($response->header('access-control-allow-origin') === '*') {
            return RuleStatus::ok(
                rule: 'CORS',
                message: 'Access-Control-Allow-Origin: * allows any site to read public responses (without cookies)',
            );
        }

        return RuleStatus::ok(
            rule: 'CORS',
            message: 'Foreign origins are not allowed',
        );
    }
}
