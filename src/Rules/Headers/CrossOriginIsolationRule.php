<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.cross-origin-isolation',
    name: 'Cross-Origin policies',
    category: 'Headers',
    description: 'Checks Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy. COOP separates the page from windows of other sites (window.open, opener), which blocks cross-site leaks (XS-Leaks) and tabnabbing. CORP stops other sites from loading the response as a resource, which limits Spectre-style side-channel attacks. Cross-Origin-Embedder-Policy is reported for information only.',
    remediation: <<<'TXT'
        Cross-Origin-Opener-Policy: same-origin
        (same-origin-allow-popups when the page opens OAuth or payment popups)
        Cross-Origin-Resource-Policy: same-origin
        (same-site when subdomains load the resources, cross-origin for public CDN files)
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
        'https://xsleaks.dev/',
    ],
)]
final class CrossOriginIsolationRule implements RuleInterface
{
    private const array SAFE_OPENER_POLICIES = ['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'];

    private const array SAFE_RESOURCE_POLICIES = ['same-origin', 'same-site'];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $opener = $this->policy($response, 'cross-origin-opener-policy');
        $resource = $this->policy($response, 'cross-origin-resource-policy');
        $embedder = $this->policy($response, 'cross-origin-embedder-policy');

        $warnings = [];

        if ($opener === null) {
            $warnings[] = 'Cross-Origin-Opener-Policy is missing, windows of other sites can access the page';
        } elseif (!in_array($opener, self::SAFE_OPENER_POLICIES, true)) {
            $warnings[] = sprintf('Cross-Origin-Opener-Policy: %s does not isolate the page from other sites', $opener);
        }

        if ($resource === null) {
            $warnings[] = 'Cross-Origin-Resource-Policy is missing, other sites can load the page as a resource';
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Cross-Origin policies',
                message: implode('; ', $warnings),
            );
        }

        $summary = [
            sprintf('COOP: %s', $opener),
            in_array($resource, self::SAFE_RESOURCE_POLICIES, true)
                ? sprintf('CORP: %s', $resource)
                : sprintf('CORP: %s (any site may load the response)', $resource),
            sprintf('COEP: %s', $embedder ?? 'not set'),
        ];

        return RuleStatus::ok(
            rule: 'Cross-Origin policies',
            message: implode(', ', $summary),
        );
    }

    /**
     * Policy value without parameters, e.g. "same-origin" from 'same-origin; report-to="coop"'.
     */
    private function policy(HttpResponseInterface $response, string $header): ?string
    {
        $value = $response->header($header);

        if ($value === null) {
            return null;
        }

        $policy = strtolower(trim(explode(';', $value)[0]));

        return $policy === '' ? null : $policy;
    }
}
