<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Content;

use DOMElement;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'content.subresource-integrity',
    name: 'Subresource Integrity',
    category: 'Content',
    description: 'Checks that scripts and stylesheets loaded from other domains (CDNs) have an integrity attribute. Without it, a compromised CDN can serve modified code that runs on the page. With integrity, cross-origin resources also need the crossorigin attribute, otherwise the browser blocks them.',
    remediation: <<<'TXT'
        <script src="https://cdn.example.com/lib.js" integrity="sha384-…" crossorigin="anonymous"></script>
        Generate the hash: openssl dgst -sha384 -binary lib.js | openssl base64 -A
        Resources that change on every request (e.g. analytics, font CSS) cannot use SRI, host them yourself if possible.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
    ],
)]
final class SubresourceIntegrityRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $xpath = $response->xpath();
        $pageHost = $response->host();

        if (!$xpath instanceof \DOMXPath || $pageHost === null) {
            return RuleStatus::skip(
                rule: 'Subresource Integrity',
                message: 'Page has no content to check',
            );
        }

        $resources = [];

        foreach ($xpath->query('//script[@src]') ?: [] as $element) {
            if ($element instanceof DOMElement) {
                $resources[] = [$element, $element->getAttribute('src')];
            }
        }

        foreach ($xpath->query('//link[contains(concat(" ", normalize-space(@rel), " "), " stylesheet ")][@href]') ?: [] as $element) {
            if ($element instanceof DOMElement) {
                $resources[] = [$element, $element->getAttribute('href')];
            }
        }

        $external = 0;
        $missingIntegrity = [];
        $missingCrossOrigin = [];

        foreach ($resources as [$element, $url]) {
            if (!$this->isExternal(trim($url), $pageHost)) {
                continue;
            }

            $external++;

            if (!$element->hasAttribute('integrity')) {
                $missingIntegrity[] = trim($url);
            } elseif (!$element->hasAttribute('crossorigin')) {
                $missingCrossOrigin[] = trim($url);
            }
        }

        if ($external === 0) {
            return RuleStatus::skip(
                rule: 'Subresource Integrity',
                message: 'No scripts or stylesheets are loaded from other domains',
            );
        }

        $warnings = [];

        if ($missingIntegrity !== []) {
            $warnings[] = sprintf('%d of %d external resources have no integrity attribute (e.g. %s)', count($missingIntegrity), $external, $missingIntegrity[0]);
        }

        if ($missingCrossOrigin !== []) {
            $warnings[] = sprintf('%d resources have integrity but no crossorigin attribute and will be blocked (e.g. %s)', count($missingCrossOrigin), $missingCrossOrigin[0]);
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Subresource Integrity',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'Subresource Integrity',
            message: sprintf('All %d external resources are protected by integrity', $external),
        );
    }

    /**
     * Absolute or protocol-relative URL pointing outside the page's site (subdomains count as the same site).
     */
    private function isExternal(string $url, string $pageHost): bool
    {
        if (!preg_match('~^(https?:)?//~i', $url)) {
            return false;
        }

        $host = parse_url(str_starts_with($url, '//') ? 'https:' . $url : $url, PHP_URL_HOST);

        if (!is_string($host)) {
            return false;
        }

        $host = strtolower($host);
        $site = preg_replace('~^www\.~', '', $pageHost);

        return $host !== $pageHost && $host !== $site && !str_ends_with($host, '.' . $site);
    }
}
