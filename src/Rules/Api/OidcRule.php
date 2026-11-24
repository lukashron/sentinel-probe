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

#[Rule(
    id: 'api.oidc',
    name: 'OpenID Connect',
    category: 'API',
    description: 'Reads the OpenID Connect / OAuth 2.0 discovery documents (/.well-known/openid-configuration, /.well-known/oauth-authorization-server) and checks the advertised flows: the implicit flow (response types with token) puts tokens into URLs and browser history, the resource owner password grant hands passwords to clients, missing PKCE with S256 allows stealing authorization codes, and endpoints over plain HTTP leak tokens. OAuth 2.1 and the OAuth Security BCP (RFC 9700) deprecate all of them.',
    remediation: <<<'TXT'
        Offer only the authorization code flow with PKCE: response_types_supported ["code"], code_challenge_methods_supported ["S256"].
        Disable the implicit and password grants in the identity provider (Keycloak, Auth0, Okta, IdentityServer, …).
        Serve the issuer and all endpoints over HTTPS only.
        TXT,
    references: [
        'https://www.rfc-editor.org/rfc/rfc9700',
        'https://openid.net/specs/openid-connect-discovery-1_0.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html',
    ],
)]
final readonly class OidcRule implements RuleInterface
{
    private const array DOCUMENTS = ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'];

    private const array ENDPOINT_KEYS = ['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'];

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());
        $document = $origin === null ? null : $this->discovery($origin);

        if ($document === null) {
            return RuleStatus::skip(
                rule: 'OpenID Connect',
                message: 'No OpenID Connect or OAuth discovery document found',
            );
        }

        [$path, $config] = $document;
        $failures = [];
        $warnings = [];

        foreach (self::ENDPOINT_KEYS as $key) {
            $url = $config[$key] ?? null;

            if (is_string($url) && str_starts_with(strtolower($url), 'http://')) {
                $failures[] = sprintf('%s uses plain HTTP: %s', $key, $url);
            }
        }

        $implicit = array_values(array_filter(
            $this->strings($config['response_types_supported'] ?? null),
            static fn(string $type): bool => in_array('token', preg_split('~\s+~', $type) ?: [], true),
        ));

        if ($implicit !== []) {
            $warnings[] = sprintf('implicit flow is offered (%s), tokens end up in URLs', implode(', ', $implicit));
        }

        $grants = $this->strings($config['grant_types_supported'] ?? null);

        if (in_array('implicit', $grants, true) && $implicit === []) {
            $warnings[] = 'implicit grant is offered, tokens end up in URLs';
        }

        if (in_array('password', $grants, true)) {
            $warnings[] = "resource owner password grant is offered, clients get the users' passwords";
        }

        $pkce = $this->strings($config['code_challenge_methods_supported'] ?? null);

        if (!in_array('S256', $pkce, true)) {
            $warnings[] = $pkce === []
                ? 'PKCE support is not advertised (code_challenge_methods_supported), authorization codes can be stolen'
                : sprintf('PKCE supports only %s, S256 is required', implode(', ', $pkce));
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'OpenID Connect',
                message: sprintf('%s: %s', $path, implode('; ', [...$failures, ...$warnings])),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'OpenID Connect',
                message: sprintf('%s: %s', $path, implode('; ', $warnings)),
            );
        }

        return RuleStatus::ok(
            rule: 'OpenID Connect',
            message: sprintf('%s: authorization code flow with PKCE S256, no implicit or password grant', $path),
        );
    }

    /**
     * @return array{string, array<mixed>}|null path and the decoded document
     */
    private function discovery(string $origin): ?array
    {
        $requests = [];

        foreach (self::DOCUMENTS as $path) {
            $requests[$path] = $this->httpClient->request('GET', $origin . $path, ['timeout' => 10]);
        }

        foreach ($requests as $path => $request) {
            try {
                $document = new HttpResponse($request);
            } catch (TransportExceptionInterface) {
                continue;
            }

            $config = $document->isSuccessful() ? json_decode($document->content(), true) : null;

            if (is_array($config) && is_string($config['issuer'] ?? null)) {
                return [(string)$path, $config];
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function strings(mixed $value): array
    {
        return is_array($value) ? array_values(array_filter($value, is_string(...))) : [];
    }
}
