<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Content;

use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'content.vulnerable-libraries',
    name: 'Vulnerable libraries',
    category: 'Content',
    description: 'Detects versions of popular frontend libraries (jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Moment, Handlebars, DOMPurify) from script URLs (CDN paths, file names) and from license banners of the page and same-origin scripts, and compares them with known vulnerable versions. Libraries that are no longer maintained are reported as a warning. Bundled libraries without a banner and versions hidden by the build cannot be detected.',
    remediation: <<<'TXT'
        Update every reported library to the latest version of its major release, or migrate when the major release is end-of-life.
        Watch dependencies automatically: npm audit, GitHub Dependabot or Renovate.
        Replace AngularJS (e.g. with Angular, Vue or React) and Moment (e.g. with Luxon, date-fns or Temporal).
        TXT,
    references: [
        'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
        'https://retirejs.github.io/retire.js/',
        'https://security.snyk.io/',
    ],
)]
final readonly class VulnerableLibrariesRule implements RuleInterface
{
    private const int MAX_SCRIPTS = 10;

    /** Banners are usually at the start, but bundles concatenate many libraries. */
    private const int MAX_SCRIPT_BYTES = 1024 * 1024;

    private PageAssets $pageAssets;

    public function __construct(
        HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $xpath = $response->xpath();

        if (!$xpath instanceof DOMXPath) {
            return RuleStatus::ok(
                rule: 'Vulnerable libraries',
                message: 'Page has no content to check',
            );
        }

        /** @var array<string, array{library: string, version: string, locations: list<string>}> $detected "library version" => detection */
        $detected = [];

        $add = static function (string $library, string $version, string $location) use (&$detected): void {
            $key = $library . ' ' . $version;
            $detected[$key] ??= ['library' => $library, 'version' => $version, 'locations' => []];

            if (!in_array($location, $detected[$key]['locations'], true)) {
                $detected[$key]['locations'][] = $location;
            }
        };

        // versions in URLs of all scripts, including CDNs
        foreach ($xpath->query('//script[@src]/@src') ?: [] as $attribute) {
            $url = PageAssets::resolve($response->url(), (string)$attribute->nodeValue);
            $path = $url === null ? null : parse_url($url, PHP_URL_PATH);

            if (!is_string($url) || !is_string($path)) {
                continue;
            }

            foreach (VulnerableLibraries::all() as $library => $definition) {
                if (preg_match('~/(?:' . $definition['url'] . ')(?:@|-|/)v?(\d+\.\d+\.\d+)~i', $path, $match) === 1) {
                    $add($library, $match[1], $url);
                }
            }
        }

        // license banners in the page and same-origin scripts
        $sources = ['the page' => $response->content()];
        $scripts = $this->pageAssets->scripts($xpath, $response->url(), self::MAX_SCRIPTS);

        foreach ($this->pageAssets->download($scripts, self::MAX_SCRIPT_BYTES) as $url => $content) {
            $sources[$url] = $content;
        }

        foreach ($sources as $location => $content) {
            foreach (VulnerableLibraries::all() as $library => $definition) {
                if ($definition['banner'] !== null && preg_match($definition['banner'], $content, $match) === 1) {
                    $add($library, $match[1], (string)$location);
                }
            }
        }

        if ($detected === []) {
            return RuleStatus::ok(
                rule: 'Vulnerable libraries',
                message: sprintf('No known library versions detected on the page and in %d scripts', count($sources) - 1),
            );
        }

        $vulnerable = [];
        $unmaintained = [];
        $safe = [];

        foreach ($detected as $detection) {
            $definition = VulnerableLibraries::all()[$detection['library']];
            $label = sprintf('%s %s', $detection['library'], $detection['version']);
            $issues = $this->vulnerabilities($detection['version'], $definition['vulns']);

            if ($issues !== []) {
                $vulnerable[] = sprintf('%s (%s) in %s', $label, implode('; ', $issues), implode(', ', $detection['locations']));
            } elseif ($definition['eol'] !== null) {
                $unmaintained[] = sprintf('%s: %s', $label, $definition['eol']);
            } else {
                $safe[] = $label;
            }

            // end-of-life is worth mentioning next to the vulnerabilities as well
            if ($issues !== [] && $definition['eol'] !== null) {
                $unmaintained[] = sprintf('%s: %s', $label, $definition['eol']);
            }
        }

        if ($vulnerable !== []) {
            return RuleStatus::fail(
                rule: 'Vulnerable libraries',
                message: implode('; ', [...$vulnerable, ...$unmaintained]),
            );
        }

        if ($unmaintained !== []) {
            return RuleStatus::warning(
                rule: 'Vulnerable libraries',
                message: implode('; ', $unmaintained),
            );
        }

        return RuleStatus::ok(
            rule: 'Vulnerable libraries',
            message: sprintf('No known vulnerabilities in %s', implode(', ', $safe)),
        );
    }

    /**
     * @param list<array{?string, string, string, string}> $vulns
     * @return list<string> "CVE list: summary"
     */
    private function vulnerabilities(string $version, array $vulns): array
    {
        $issues = [];

        foreach ($vulns as [$min, $max, $cves, $summary]) {
            if (($min === null || version_compare($version, $min, '>=')) && version_compare($version, $max, '<')) {
                $issues[] = sprintf('%s: %s', $cves, $summary);
            }
        }

        return $issues;
    }
}
