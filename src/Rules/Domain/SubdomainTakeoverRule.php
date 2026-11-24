<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Domain;

use LukasHron\SentinelProbe\Dns\DnsResolver;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'domain.subdomain-takeover',
    name: 'Subdomain takeover',
    category: 'Domain',
    description: 'Follows the CNAME records of the target host (and of its www. variant) and checks whether they point to a cloud or hosting service (Amazon S3, Heroku, Azure, GitHub Pages, Shopify, Fastly, …) where the resource no longer exists: the CNAME target does not resolve, or the target page shows the service\'s "unknown site" error. Anybody can then register the resource and serve content on your domain, including reading its cookies. Other subdomains are not enumerated.',
    remediation: <<<'TXT'
        Remove the DNS record (CNAME) as soon as the service resource is deleted, or claim the resource again.
        Delete DNS records before deprovisioning the cloud resource, not after.
        TXT,
    references: [
        'https://github.com/EdOverflow/can-i-take-over-xyz',
        'https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers',
    ],
)]
final readonly class SubdomainTakeoverRule implements RuleInterface
{
    private const int MAX_CNAME_HOPS = 5;

    /** CNAME target pattern => [service, fingerprint of the "resource does not exist" page or null] */
    private const array SERVICES = [
        '~\.s3([.-][a-z0-9-]+)*\.amazonaws\.com$|\.s3-website[.-][a-z0-9.-]+\.amazonaws\.com$~' => ['Amazon S3', '~NoSuchBucket|The specified bucket does not exist~'],
        '~\.elasticbeanstalk\.com$~' => ['AWS Elastic Beanstalk', null],
        '~\.heroku(app|dns)\.com$|\.herokudns\.com$~' => ['Heroku', '~No such app|herokucdn\.com/error-pages/no-such-app~'],
        '~\.azurewebsites\.net$~' => ['Azure App Service', '~404 Web Site not found~'],
        '~\.cloudapp\.(net|azure\.com)$~' => ['Azure', null],
        '~\.trafficmanager\.net$~' => ['Azure Traffic Manager', null],
        '~\.blob\.core\.windows\.net$~' => ['Azure Blob Storage', '~BlobServiceNotFound|The specified account does not exist~'],
        '~\.azureedge\.net$~' => ['Azure CDN', null],
        '~\.github\.io$~' => ['GitHub Pages', "~There isn't a GitHub Pages site here~"],
        '~\.bitbucket\.io$~' => ['Bitbucket', '~Repository not found~'],
        '~\.myshopify\.com$~' => ['Shopify', '~Sorry, this shop is currently unavailable~'],
        '~\.fastly\.net$~' => ['Fastly', '~Fastly error: unknown domain~'],
        '~\.pantheonsite\.io$~' => ['Pantheon', '~The gods are wise|404 error unknown site~'],
        '~\.surge\.sh$~' => ['Surge', '~project not found~'],
        '~\.ghost\.io$~' => ['Ghost', '~Domain error|The thing you were looking for is no longer here~'],
        '~\.wordpress\.com$~' => ['WordPress.com', '~Do you want to register~'],
        '~\.helpscoutdocs\.com$~' => ['Help Scout', '~No settings were found for this company~'],
        '~\.zendesk\.com$~' => ['Zendesk', '~Help Center Closed~'],
        '~\.readme\.io$~' => ['ReadMe', '~Project doesnt exist~'],
    ];

    public function __construct(
        private DnsResolver $dns,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $host = $response->host();

        if ($host === null || DnsResolver::isIpAddress($host)) {
            return RuleStatus::skip(
                rule: 'Subdomain takeover',
                message: 'Target is not addressed by a domain name',
            );
        }

        $hosts = [$host];

        if (!str_starts_with($host, 'www.')) {
            $hosts[] = 'www.' . $host;
        }

        $failures = [];
        $summary = [];

        foreach ($hosts as $name) {
            $chain = $this->cnameChain($name);

            if ($chain === []) {
                continue;
            }

            $target = $chain[count($chain) - 1];
            $summary[] = sprintf('%s → %s', $name, implode(' → ', $chain));
            $service = $this->service($chain);

            if ($service === null) {
                continue;
            }

            [$label, $fingerprint] = $service;

            if (!$this->dns->resolves($target)) {
                $failures[] = sprintf('%s points to %s (%s), which does not resolve, the resource can be registered by anybody', $name, $target, $label);
            } elseif ($name === $host && $fingerprint !== null && $response->contentMatches($fingerprint)) {
                $failures[] = sprintf('%s points to %s (%s), which shows the "resource does not exist" page, the resource can be claimed by anybody', $name, $target, $label);
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'Subdomain takeover',
                message: implode('; ', $failures),
            );
        }

        return RuleStatus::ok(
            rule: 'Subdomain takeover',
            message: $summary === []
                ? sprintf('%s has no CNAME record', implode(' and ', $hosts))
                : sprintf('CNAME targets are claimed: %s', implode('; ', $summary)),
        );
    }

    /**
     * @return list<string> CNAME targets in order
     */
    private function cnameChain(string $name): array
    {
        $chain = [];

        for ($hop = 0; $hop < self::MAX_CNAME_HOPS; $hop++) {
            $target = $this->dns->cname($name);

            if ($target === null || in_array($target, $chain, true)) {
                break;
            }

            $chain[] = $target;
            $name = $target;
        }

        return $chain;
    }

    /**
     * @param list<string> $chain
     * @return array{string, ?string}|null
     */
    private function service(array $chain): ?array
    {
        foreach ($chain as $target) {
            foreach (self::SERVICES as $pattern => $service) {
                if (preg_match($pattern, $target) === 1) {
                    return $service;
                }
            }
        }

        return null;
    }
}
