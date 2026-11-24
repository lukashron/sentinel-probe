<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.csp',
    name: 'CSP',
    category: 'Headers',
    description: "Checks the Content-Security-Policy, which limits where scripts and other resources can load from and is the main defense against XSS. All enforced policies are evaluated together: every header, comma-separated policies and <meta http-equiv> policies. Warns about 'unsafe-inline', 'unsafe-eval', overly permissive sources (*, https:, data:, blob:, filesystem:), hosts known to serve JSONP or arbitrary libraries that bypass the policy (Google APIs, cdnjs, jsDelivr, unpkg, …), a missing object-src and a missing base-uri (an injected <base> tag redirects relative scripts and bypasses nonces).",
    remediation: <<<'TXT'
        Content-Security-Policy: default-src 'self'; script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'
        For inline scripts use nonces or hashes instead of 'unsafe-inline'.
        Do not allow whole CDNs (cdnjs, jsDelivr, unpkg) or Google domains, they host scripts that execute attacker-chosen code; use nonces with 'strict-dynamic' or exact file URLs.
        TXT,
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
        'https://csp-evaluator.withgoogle.com/',
    ],
)]
final class ContentSecurityPolicyRule implements RuleInterface
{
    /** Sources allowing scripts from anywhere or from attacker-controlled content */
    private const array PERMISSIVE_SOURCES = ['*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:'];

    /**
     * Hosts serving JSONP endpoints, Angular or other libraries that execute attacker-chosen code,
     * or content anybody can upload. Allowing them in script-src bypasses the policy.
     */
    private const array BYPASS_HOSTS = [
        'googleapis.com', 'gstatic.com', 'google.com', 'googleusercontent.com', 'appspot.com',
        'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'raw.githubusercontent.com', 'github.io',
        'cloudfront.net', 'amazonaws.com', 'azureedge.net', 'firebaseapp.com', 'herokuapp.com',
    ];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $policies = $response->contentSecurityPolicies();

        if ($policies === []) {
            if ($response->reportOnlyContentSecurityPolicies() !== []) {
                return RuleStatus::warning(
                    rule: 'CSP',
                    message: 'Policy runs only in Report-Only mode and is not enforced',
                );
            }

            return RuleStatus::fail(
                rule: 'CSP',
                message: 'Content-Security-Policy header is missing',
            );
        }

        $parsed = array_map(self::parse(...), $policies);
        $issues = [...$this->scriptIssues($parsed), ...$this->objectIssues($parsed), ...$this->baseIssues($parsed)];

        $headerCount = count($response->contentSecurityPolicies(true));
        $metaCount = count($policies) - $headerCount;
        $origin = $metaCount > 0
            ? sprintf(' (%d header and %d <meta> policies)', $headerCount, $metaCount)
            : (count($policies) > 1 ? sprintf(' (%d policies)', count($policies)) : '');

        if ($issues !== []) {
            return RuleStatus::warning(
                rule: 'CSP',
                message: 'Weak policy' . $origin . ': ' . implode('; ', $issues),
            );
        }

        return RuleStatus::ok(
            rule: 'CSP',
            message: 'Content-Security-Policy restricts scripts, plugins and <base>' . $origin,
        );
    }

    /**
     * @return array<string, string> lowercase directive name => source list
     */
    public static function parse(string $policy): array
    {
        $directives = [];

        foreach (explode(';', $policy) as $directive) {
            $parts = preg_split('~\s+~', trim($directive), 2) ?: [];
            $name = strtolower($parts[0] ?? '');

            // the first occurrence of a directive wins
            if ($name !== '' && !isset($directives[$name])) {
                $directives[$name] = trim($parts[1] ?? '');
            }
        }

        return $directives;
    }

    /**
     * Policies are enforced together, so scripts are restricted when at least one policy restricts them well.
     *
     * @param list<array<string, string>> $policies
     * @return list<string>
     */
    private function scriptIssues(array $policies): array
    {
        $best = null;

        foreach ($policies as $directives) {
            $sources = $directives['script-src'] ?? $directives['default-src'] ?? null;

            if ($sources === null) {
                continue;
            }

            $issues = $this->weakScriptSources($sources);

            if ($best === null || count($issues) < count($best)) {
                $best = $issues;
            }
        }

        return $best ?? ['neither script-src nor default-src is set, scripts are not restricted'];
    }

    /**
     * @return list<string>
     */
    private function weakScriptSources(string $sources): array
    {
        $lower = strtolower($sources);
        $tokens = preg_split('~\s+~', $lower, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $hasNonceOrHash = preg_match("~'(nonce-|sha256-|sha384-|sha512-)~", $lower) === 1;
        $strictDynamic = in_array("'strict-dynamic'", $tokens, true);
        $issues = [];

        if (in_array("'unsafe-inline'", $tokens, true) && !$hasNonceOrHash) {
            $issues[] = "'unsafe-inline' allows inline scripts (XSS)";
        }

        if (in_array("'unsafe-eval'", $tokens, true)) {
            $issues[] = "'unsafe-eval' allows eval()";
        }

        // browsers ignore host and scheme sources when 'strict-dynamic' is present
        if ($strictDynamic) {
            return $issues;
        }

        $bypasses = [];

        foreach ($tokens as $source) {
            if (in_array($source, self::PERMISSIVE_SOURCES, true)) {
                $issues[] = sprintf("'%s' allows scripts from any origin or attacker-created content", $source);
            } elseif ($this->isBypassHost($source)) {
                $bypasses[] = $source;
            }
        }

        if ($bypasses !== []) {
            $issues[] = sprintf('%s host JSONP endpoints or libraries that bypass the policy', implode(', ', $bypasses));
        }

        return $issues;
    }

    /**
     * @param list<array<string, string>> $policies
     * @return list<string>
     */
    private function objectIssues(array $policies): array
    {
        $defined = false;

        foreach ($policies as $directives) {
            $sources = $directives['object-src'] ?? $directives['default-src'] ?? null;

            if ($sources === null) {
                continue;
            }

            $defined = true;
            $tokens = preg_split('~\s+~', strtolower($sources), -1, PREG_SPLIT_NO_EMPTY) ?: [];

            if (array_intersect($tokens, self::PERMISSIVE_SOURCES) === []) {
                return [];
            }
        }

        return $defined
            ? ["object-src allows plugins from any origin, use object-src 'none'"]
            : ["object-src is not set, <object> and <embed> can load scripts, use object-src 'none'"];
    }

    /**
     * base-uri does not fall back to default-src.
     *
     * @param list<array<string, string>> $policies
     * @return list<string>
     */
    private function baseIssues(array $policies): array
    {
        $usesNonces = false;

        foreach ($policies as $directives) {
            $sources = $directives['base-uri'] ?? null;

            if ($sources !== null) {
                $tokens = preg_split('~\s+~', strtolower($sources), -1, PREG_SPLIT_NO_EMPTY) ?: [];

                if (array_intersect($tokens, self::PERMISSIVE_SOURCES) === []) {
                    return [];
                }
            }

            $usesNonces = $usesNonces || preg_match("~'(nonce-|sha256-|sha384-|sha512-)~i", $directives['script-src'] ?? $directives['default-src'] ?? '') === 1;
        }

        return [$usesNonces
            ? "base-uri is not restricted, an injected <base> tag redirects relative scripts and bypasses the nonces, use base-uri 'none' or 'self'"
            : "base-uri is not restricted, an injected <base> tag redirects relative URLs, use base-uri 'none' or 'self'"];
    }

    private function isBypassHost(string $source): bool
    {
        if (str_starts_with($source, "'")) {
            return false;
        }

        $host = (string)preg_replace(['~^[a-z][a-z0-9+.-]*://~', '~[/:].*$~'], '', $source);
        $isWildcard = str_starts_with($host, '*.');
        $host = $isWildcard ? substr($host, 2) : $host;

        if ($host === '') {
            return false;
        }

        foreach (self::BYPASS_HOSTS as $bypass) {
            // the source is the bypass host or its subdomain, or a wildcard covering the bypass host
            if ($host === $bypass || str_ends_with($host, '.' . $bypass) || ($isWildcard && str_ends_with($bypass, '.' . $host))) {
                return true;
            }
        }

        return false;
    }
}
