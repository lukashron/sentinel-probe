<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\Origin;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.framework-endpoints',
    name: 'Framework endpoints',
    category: 'Exposure',
    description: 'Looks for debugging and administration endpoints of frameworks that must not be public: Spring Boot Actuator (/actuator/env with configuration and secrets, /actuator/heapdump with the whole memory including passwords and sessions), Laravel Telescope, Horizon and Ignition (CVE-2021-3129), the Symfony profiler, Rails routes, ELMAH, the Werkzeug debugger console (remote code execution) and database tools (Adminer, phpMyAdmin). An endpoint is reported only when its content matches the tool.',
    remediation: <<<'TXT'
        Spring Boot: management.endpoints.web.exposure.include=health,info and put the rest behind authentication (or management.server.port on an internal network).
        Laravel: install Telescope and Ignition as dev dependencies only, protect Horizon and Telescope with their gate, APP_DEBUG=false.
        Symfony: APP_ENV=prod, the web profiler only in dev. Flask/Werkzeug: never run with debug=True in production.
        Database tools: remove them from the web server or restrict them by IP and VPN.
        TXT,
    references: [
        'https://docs.spring.io/spring-boot/reference/actuator/endpoints.html',
        'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
)]
final readonly class FrameworkEndpointsRule implements RuleInterface
{
    /** path => [content pattern, description, critical] */
    private const array ENDPOINTS = [
        '/actuator/env' => ['~"(propertySources|activeProfiles)"\s*:~', 'Spring Boot Actuator environment with configuration and secrets', true],
        '/actuator/heapdump' => ['~^JAVA PROFILE \d~', 'Spring Boot Actuator heap dump with passwords and sessions from memory', true],
        '/actuator/mappings' => ['~"(dispatcherServlets|mappings)"\s*:~', 'Spring Boot Actuator list of all routes', false],
        '/actuator' => ['~"_links"\s*:.*"self"~s', 'Spring Boot Actuator index', false],
        '/telescope/requests' => ['~window\.Telescope|<title>[^<]*Telescope~', 'Laravel Telescope with requests, queries and exceptions of all visitors', true],
        '/horizon/dashboard' => ['~window\.Horizon|<title>[^<]*Horizon~', 'Laravel Horizon with queued jobs and their data', true],
        '/_ignition/health-check' => ['~"can_execute_commands"\s*:~', 'Laravel Ignition (remote code execution in old versions, CVE-2021-3129)', true],
        '/_profiler/empty/search/results?limit=10' => ['~Symfony Profiler~', 'Symfony profiler with requests of all visitors', true],
        '/rails/info/routes' => ['~Routes.*Helper.*HTTP Verb~s', 'Rails development route list', true],
        '/elmah.axd' => ['~Error Log for~', 'ELMAH error log', true],
        '/console' => ['~Werkzeug.*[Cc]onsole|__debugger__~s', 'Werkzeug debugger console (remote code execution)', true],
        '/adminer.php' => ['~<title>[^<]*Adminer~', 'Adminer database tool', false],
        '/phpmyadmin/' => ['~<title>[^<]*phpMyAdmin~', 'phpMyAdmin database tool', false],
    ];

    /** Only the beginning of each response is downloaded, heap dumps are huge. */
    private const int MAX_BYTES = 16384;

    private PageAssets $pageAssets;

    public function __construct(
        HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());

        if ($origin === null) {
            return RuleStatus::skip(
                rule: 'Framework endpoints',
                message: sprintf('Could not determine the target origin from %s', $response->url()),
            );
        }

        $urls = [];

        foreach (array_keys(self::ENDPOINTS) as $path) {
            $urls[$origin . $path] = $path;
        }

        $critical = [];
        $other = [];

        foreach ($this->pageAssets->download(array_keys($urls), self::MAX_BYTES) as $url => $content) {
            $path = $urls[$url] ?? null;

            if ($path === null) {
                continue;
            }

            [$pattern, $description, $isCritical] = self::ENDPOINTS[$path];

            if (preg_match($pattern, $content) === 1) {
                $finding = sprintf('%s (%s)', explode('?', $path)[0], $description);

                if ($isCritical) {
                    $critical[] = $finding;
                } else {
                    $other[] = $finding;
                }
            }
        }

        if ($critical !== []) {
            return RuleStatus::fail(
                rule: 'Framework endpoints',
                message: sprintf('Publicly accessible: %s', implode('; ', [...$critical, ...$other])),
            );
        }

        if ($other !== []) {
            return RuleStatus::warning(
                rule: 'Framework endpoints',
                message: sprintf('Publicly accessible: %s', implode('; ', $other)),
            );
        }

        return RuleStatus::ok(
            rule: 'Framework endpoints',
            message: sprintf('None of %d framework debugging and administration endpoints is accessible', count(self::ENDPOINTS)),
        );
    }
}
