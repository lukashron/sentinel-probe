<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Transport;

use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\Headers\ContentSecurityPolicyRule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'transport.mixed-content',
    name: 'Mixed content',
    category: 'Transport',
    description: 'Checks that an HTTPS page does not load resources or submit forms over plain HTTP. Browsers block active mixed content (scripts, styles, iframes), which breaks the page, and forms sent over HTTP expose the entered data. Passive content (images, media) can be read or replaced in transit.',
    remediation: <<<'TXT'
        Load all resources over https:// (or relative URLs) and submit forms to https:// addresses.
        As a safety net add: Content-Security-Policy: upgrade-insecure-requests
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
    ],
)]
final class MixedContentRule implements RuleInterface
{
    /** XPath => label; blocked by browsers or exposing submitted data */
    private const array ACTIVE = [
        '//script[@src]/@src' => '<script>',
        '//link[contains(concat(" ", normalize-space(@rel), " "), " stylesheet ")]/@href' => '<link rel=stylesheet>',
        '//iframe[@src]/@src' => '<iframe>',
        '//frame[@src]/@src' => '<frame>',
        '//object[@data]/@data' => '<object>',
        '//embed[@src]/@src' => '<embed>',
        '//form[@action]/@action' => '<form action>',
    ];

    /** XPath => label; loaded by browsers but readable and replaceable in transit */
    private const array PASSIVE = [
        '//img[@src]/@src' => '<img>',
        '//audio[@src]/@src' => '<audio>',
        '//video[@src]/@src' => '<video>',
        '//source[@src]/@src' => '<source>',
    ];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        if (!$response->isHttps()) {
            return RuleStatus::warning(
                rule: 'Mixed content',
                message: 'Site is not served over HTTPS, the whole page is unencrypted',
            );
        }

        $xpath = $response->xpath();

        if (!$xpath instanceof \DOMXPath) {
            return RuleStatus::ok(
                rule: 'Mixed content',
                message: 'Page has no content to check',
            );
        }

        $active = $this->findInsecure($xpath, self::ACTIVE);
        $passive = $this->findInsecure($xpath, self::PASSIVE);

        if ($active === [] && $passive === []) {
            return RuleStatus::ok(
                rule: 'Mixed content',
                message: 'All resources and forms use HTTPS',
            );
        }

        $policy = $response->header('content-security-policy');

        if ($policy !== null && array_key_exists('upgrade-insecure-requests', ContentSecurityPolicyRule::parse($policy))) {
            return RuleStatus::warning(
                rule: 'Mixed content',
                message: 'HTTP resources are upgraded by CSP upgrade-insecure-requests, fix the URLs anyway: ' . $this->summary([...$active, ...$passive]),
            );
        }

        if ($active !== []) {
            return RuleStatus::fail(
                rule: 'Mixed content',
                message: 'Loaded or submitted over HTTP: ' . $this->summary([...$active, ...$passive]),
            );
        }

        return RuleStatus::warning(
            rule: 'Mixed content',
            message: 'Passive content loaded over HTTP: ' . $this->summary($passive),
        );
    }

    /**
     * @param array<string, string> $queries XPath => label
     * @return array<string, list<string>> label => insecure URLs
     */
    private function findInsecure(DOMXPath $xpath, array $queries): array
    {
        $found = [];

        foreach ($queries as $query => $label) {
            foreach ($xpath->query($query) ?: [] as $attribute) {
                $url = trim((string)$attribute->nodeValue);

                if (stripos($url, 'http://') === 0) {
                    $found[$label][] = $url;
                }
            }
        }

        return $found;
    }

    /**
     * @param array<string, list<string>> $found
     */
    private function summary(array $found): string
    {
        $parts = [];

        foreach ($found as $label => $urls) {
            $parts[] = sprintf('%s %d× (e.g. %s)', $label, count($urls), $urls[0]);
        }

        return implode(', ', $parts);
    }
}
