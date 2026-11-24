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
    description: 'Sends requests with foreign Origin headers and checks whether the server allows them in Access-Control-Allow-Origin: a made-up domain, "null", and bypasses of broken origin validation (the target domain as a prefix of a foreign domain, a foreign domain ending with the target name, and the target over plain http://). Reflecting such an origin together with Access-Control-Allow-Credentials lets the attacker\'s website read responses with the visitor\'s cookies. CORS matters mostly on API endpoints, the target page is tested only.',
    remediation: <<<'TXT'
        Allow only a fixed list of trusted origins and compare the Origin header against it exactly (scheme, host and port).
        Never use prefix, suffix or substring matching or unanchored regular expressions, never reflect the Origin header blindly and never allow "null".
        Send Access-Control-Allow-Credentials: true only for trusted HTTPS origins that need it.
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
        $origins = $this->origins($response);

        try {
            // requests run concurrently, HttpResponse reads them afterwards
            $requests = [];

            foreach (array_keys($origins) as $origin) {
                $requests[$origin] = $this->httpClient->request('GET', $response->url(), [
                    'timeout' => 10,
                    'headers' => ['Origin' => $origin],
                ]);
            }

            $probes = array_map(static fn($request): HttpResponse => new HttpResponse($request), $requests);
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'CORS',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        $failures = [];
        $warnings = [];

        foreach ($probes as $origin => $probe) {
            $origin = (string)$origin;
            $allowed = $probe->header('access-control-allow-origin');
            $credentials = strtolower($probe->header('access-control-allow-credentials') ?? '') === 'true';

            if ($allowed !== $origin) {
                continue;
            }

            $description = $origins[$origin];

            // a plain HTTP origin of the target itself needs a man-in-the-middle attacker
            if ($credentials && !str_starts_with($description, 'the target over plain HTTP')) {
                $failures[] = sprintf('Origin "%s" (%s) is allowed with credentials, that site can read responses with the visitor\'s cookies', $origin, $description);
            } else {
                $warnings[] = sprintf('Origin "%s" (%s) is allowed%s', $origin, $description, $credentials ? ' with credentials' : '');
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
            message: sprintf('None of %d foreign origins is allowed', count($origins)),
        );
    }

    /**
     * @return array<string, string> origin => description
     */
    private function origins(HttpResponseInterface $response): array
    {
        $random = bin2hex(random_bytes(4));
        $origins = [
            sprintf('https://sentinel-probe-%s.example', $random) => 'a foreign domain, the server reflects any origin',
            'null' => 'sandboxed iframes and local files',
        ];

        $host = $response->host();

        if ($host === null) {
            return $origins;
        }

        $site = (string)preg_replace('~^www\.~', '', $host);
        $port = parse_url($response->url(), PHP_URL_PORT);
        $port = is_int($port) ? ':' . $port : '';

        $origins[sprintf('https://%s.sentinel-probe-%s.example', $site, $random)] = 'the target domain as a prefix, the server checks only the beginning';
        $origins[sprintf('https://sentinelprobe%s%s', $random, $site)] = 'a foreign domain ending with the target name, the server checks only the end';

        if ($response->isHttps()) {
            $origins[sprintf('http://%s%s', $host, $port)] = 'the target over plain HTTP, a network attacker can inject scripts into it';
        }

        return $origins;
    }
}
