<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.reporting',
    name: 'Reporting',
    category: 'Headers',
    description: 'Informs whether the application collects browser reports about violations of its security policies: the Reporting-Endpoints and legacy Report-To headers, CSP report-to and report-uri directives (including Report-Only) and report-to in COOP and COEP. Notes report-to groups that are not defined and endpoints over plain HTTP. Missing reporting is not a vulnerability, but without it CSP violations and attacks in production stay unnoticed.',
    remediation: <<<'TXT'
        Reporting-Endpoints: csp="https://example.com/reports/csp"
        Content-Security-Policy: ...; report-to csp; report-uri https://example.com/reports/csp
        (report-uri is a fallback for browsers without the Reporting API)
        Cross-Origin-Opener-Policy: same-origin; report-to="csp"
        Use HTTPS endpoints only, e.g. your own collector or a service such as report-uri.com.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to',
        'https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API',
    ],
)]
final class ReportingRule implements RuleInterface
{
    private const array POLICY_HEADERS = [
        'cross-origin-opener-policy' => 'COOP',
        'cross-origin-opener-policy-report-only' => 'COOP-Report-Only',
        'cross-origin-embedder-policy' => 'COEP',
        'cross-origin-embedder-policy-report-only' => 'COEP-Report-Only',
    ];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $endpoints = $this->endpoints($response);

        /** @var array<string, list<string>> $groups report-to group => policies reporting to it */
        $groups = [];

        /** @var list<array{policy: string, url: string}> $reportUris */
        $reportUris = [];

        // reporting directives are ignored in <meta> policies
        $cspPolicies = [
            'CSP' => $response->contentSecurityPolicies(true),
            'CSP-Report-Only' => $response->reportOnlyContentSecurityPolicies(),
        ];

        foreach ($cspPolicies as $label => $policies) {
            foreach ($policies as $policy) {
                $directives = ContentSecurityPolicyRule::parse($policy);

                foreach (preg_split('~\s+~', $directives['report-to'] ?? '', -1, PREG_SPLIT_NO_EMPTY) ?: [] as $group) {
                    $groups[$group][] = $label;
                }

                foreach (preg_split('~\s+~', $directives['report-uri'] ?? '', -1, PREG_SPLIT_NO_EMPTY) ?: [] as $uri) {
                    $reportUris[] = ['policy' => $label, 'url' => $uri];
                }
            }
        }

        foreach (self::POLICY_HEADERS as $header => $label) {
            $value = $response->header($header);

            if ($value !== null && preg_match('~;\s*report-to\s*=\s*"?([^";\s]+)"?~i', $value, $match) === 1) {
                $groups[$match[1]][] = $label;
            }
        }

        if ($endpoints === [] && $groups === [] && $reportUris === []) {
            return RuleStatus::warning(
                rule: 'Reporting',
                message: 'No reporting is configured, violations of security policies are not reported',
            );
        }

        $summary = [];
        $notes = [];

        foreach ($endpoints as $name => $url) {
            $summary[] = sprintf('%s → %s', $name, $url);

            if (str_starts_with(strtolower($url), 'http://')) {
                $notes[] = sprintf('endpoint %s uses plain HTTP', $name);
            }
        }

        foreach ($groups as $group => $policies) {
            $summary[] = sprintf('%s reports to %s', implode(', ', array_unique($policies)), $group);

            if (!isset($endpoints[$group])) {
                $notes[] = sprintf('group %s is not defined in Reporting-Endpoints or Report-To, its reports are dropped', $group);
            }
        }

        foreach ($reportUris as $reportUri) {
            $summary[] = sprintf('%s → %s', $reportUri['policy'], $reportUri['url']);

            if (str_starts_with(strtolower($reportUri['url']), 'http://')) {
                $notes[] = sprintf('report-uri %s uses plain HTTP', $reportUri['url']);
            }
        }

        $message = 'Reporting: ' . implode('; ', $summary);

        if ($notes !== []) {
            $message .= '; note: ' . implode('; ', array_unique($notes));
        }

        return RuleStatus::ok(
            rule: 'Reporting',
            message: $message,
        );
    }

    /**
     * Endpoints from Reporting-Endpoints (name="url", …) and the legacy Report-To ({"group": …, "endpoints": [{"url": …}]}, …).
     *
     * @return array<string, string> group name => first URL
     */
    private function endpoints(HttpResponseInterface $response): array
    {
        $endpoints = [];

        $reportingEndpoints = $response->headerLine('reporting-endpoints') ?? '';

        if (preg_match_all('~([a-z0-9_*.-]+)\s*=\s*"([^"]*)"~i', $reportingEndpoints, $matches, PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $endpoints[$match[1]] ??= $match[2];
            }
        }

        $reportTo = $response->headerLine('report-to');

        if ($reportTo !== null) {
            $groups = json_decode('[' . $reportTo . ']', true);

            foreach (is_array($groups) ? $groups : [] as $group) {
                if (!is_array($group)) {
                    continue;
                }

                $name = is_string($group['group'] ?? null) ? $group['group'] : 'default';
                $url = is_array($group['endpoints'] ?? null) && is_array($group['endpoints'][0] ?? null) ? ($group['endpoints'][0]['url'] ?? null) : null;

                if (is_string($url)) {
                    $endpoints[$name] ??= $url;
                }
            }
        }

        return $endpoints;
    }
}
