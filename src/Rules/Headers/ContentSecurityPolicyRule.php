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
    description: "Checks the Content-Security-Policy header, which limits where scripts and other resources can load from and is the main defense against XSS. Warns about 'unsafe-inline', 'unsafe-eval' and overly permissive sources.",
    remediation: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\nFor inline scripts use nonces or hashes instead of 'unsafe-inline'.",
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
    ],
)]
final class ContentSecurityPolicyRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $policy = $response->header('content-security-policy');

        if ($policy === null) {
            if ($response->hasHeader('content-security-policy-report-only')) {
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

        $directives = self::parse($policy);
        $scriptSources = $directives['script-src'] ?? $directives['default-src'] ?? null;

        if ($scriptSources === null) {
            return RuleStatus::warning(
                rule: 'CSP',
                message: 'Neither script-src nor default-src is set, scripts are not restricted',
            );
        }

        $issues = [];
        $hasNonceOrHash = preg_match("~'(nonce-|sha256-|sha384-|sha512-)~i", $scriptSources) === 1;

        if (str_contains($scriptSources, "'unsafe-inline'") && !$hasNonceOrHash) {
            $issues[] = "'unsafe-inline' allows inline scripts (XSS)";
        }

        if (str_contains($scriptSources, "'unsafe-eval'")) {
            $issues[] = "'unsafe-eval' allows eval()";
        }

        foreach (preg_split('~\s+~', $scriptSources) ?: [] as $source) {
            if (in_array(strtolower($source), ['*', 'http:', 'https:', 'data:'], true)) {
                $issues[] = sprintf("'%s' allows scripts from any origin", $source);
            }
        }

        if ($issues !== []) {
            return RuleStatus::warning(
                rule: 'CSP',
                message: 'Weak script policy: ' . implode('; ', $issues),
            );
        }

        return RuleStatus::ok(
            rule: 'CSP',
            message: 'Content-Security-Policy restricts scripts',
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
}
