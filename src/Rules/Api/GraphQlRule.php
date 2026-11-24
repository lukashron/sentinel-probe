<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Api;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\Origin;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[Rule(
    id: 'api.graphql',
    name: 'GraphQL',
    category: 'API',
    description: 'Looks for a GraphQL endpoint (/graphql, /api/graphql, …) and checks its hardening with read-only queries (__typename, __schema, no mutations): enabled introspection reveals the whole API schema including internal and admin operations, field suggestions ("Did you mean …") let attackers rebuild the schema even without introspection, query batching bypasses rate limiting (brute-forcing passwords or 2FA codes in one request) and queries over GET may allow CSRF.',
    remediation: <<<'TXT'
        Disable introspection and field suggestions in production:
        Apollo Server: introspection: false, and the hideSchemaDetailsFromClientErrors option (or a plugin masking suggestions)
        graphql-php / Lighthouse: DisableIntrospection rule, Lighthouse: security.disable_introspection
        Limit or disable batching, and apply rate limiting and query depth/cost limits per operation, not per HTTP request.
        Accept mutations only via POST with Content-Type: application/json.
        TXT,
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        'https://portswigger.net/web-security/graphql',
    ],
)]
final readonly class GraphQlRule implements RuleInterface
{
    private const array ENDPOINTS = ['/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql', '/query'];

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());
        $endpoint = $origin === null ? null : $this->findEndpoint($origin);

        if ($endpoint === null) {
            return RuleStatus::skip(
                rule: 'GraphQL',
                message: sprintf('No GraphQL endpoint found at %s', implode(', ', self::ENDPOINTS)),
            );
        }

        try {
            // all probes run concurrently
            $requests = [
                'introspection' => $this->post($endpoint, ['query' => '{__schema{queryType{name}}}']),
                'suggestions' => $this->post($endpoint, ['query' => '{__typenam}']),
                'batching' => $this->post($endpoint, [['query' => '{__typename}'], ['query' => '{__typename}']]),
                'get' => $this->httpClient->request('GET', $endpoint . '?query=' . rawurlencode('{__typename}'), [
                    'timeout' => 10,
                    'max_redirects' => 0,
                    'headers' => ['Accept' => 'application/json'],
                ]),
            ];

            $json = array_map(fn(ResponseInterface $request): mixed => $this->json(new HttpResponse($request)), $requests);
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'GraphQL',
                message: sprintf('GraphQL endpoint %s found, but could not be tested: %s', $endpoint, $e->getMessage()),
            );
        }

        $failures = [];
        $warnings = [];

        if (is_string($this->path($json['introspection'], 'data', '__schema', 'queryType', 'name'))) {
            $failures[] = 'introspection is enabled, the whole schema can be downloaded';
        }

        if ($this->hasSuggestion($json['suggestions'])) {
            $warnings[] = 'field suggestions ("Did you mean …") reveal the schema even without introspection';
        }

        if (is_array($json['batching']) && array_is_list($json['batching']) && count($json['batching']) === 2
            && is_string($this->path($json['batching'], 0, 'data', '__typename'))) {
            $warnings[] = 'query batching is enabled, many operations in one request bypass rate limiting';
        }

        if (is_string($this->path($json['get'], 'data', '__typename'))) {
            $warnings[] = 'queries over GET are accepted, make sure mutations are not (CSRF)';
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'GraphQL',
                message: sprintf('%s: %s', $endpoint, implode('; ', [...$failures, ...$warnings])),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'GraphQL',
                message: sprintf('%s: %s', $endpoint, implode('; ', $warnings)),
            );
        }

        return RuleStatus::ok(
            rule: 'GraphQL',
            message: sprintf('%s: introspection, field suggestions, batching and GET queries are disabled', $endpoint),
        );
    }

    /**
     * The first endpoint answering {__typename} with GraphQL JSON.
     */
    private function findEndpoint(string $origin): ?string
    {
        $requests = [];

        foreach (self::ENDPOINTS as $path) {
            $requests[$origin . $path] = $this->post($origin . $path, ['query' => '{__typename}']);
        }

        foreach ($requests as $url => $request) {
            try {
                $probe = new HttpResponse($request);
            } catch (TransportExceptionInterface) {
                continue;
            }

            if (is_string($this->path($this->json($probe), 'data', '__typename'))) {
                foreach ($requests as $other) {
                    $other->cancel();
                }

                return $url;
            }
        }

        return null;
    }

    /**
     * @param array<mixed> $body
     */
    private function post(string $url, array $body): ResponseInterface
    {
        return $this->httpClient->request('POST', $url, [
            'timeout' => 10,
            'max_redirects' => 0,
            'json' => $body,
            'headers' => ['Accept' => 'application/json'],
        ]);
    }

    private function json(HttpResponseInterface $response): mixed
    {
        return json_decode($response->content(), true);
    }

    private function path(mixed $value, int|string ...$keys): mixed
    {
        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }

            $value = $value[$key];
        }

        return $value;
    }

    private function hasSuggestion(mixed $json): bool
    {
        $errors = $this->path($json, 'errors');

        foreach (is_array($errors) ? $errors : [] as $error) {
            $message = $this->path($error, 'message');

            if (is_string($message) && stripos($message, 'did you mean') !== false) {
                return true;
            }
        }

        return false;
    }
}
