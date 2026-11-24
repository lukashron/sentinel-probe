<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Transport;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'transport.hsts',
    name: 'HSTS',
    category: 'Transport',
    description: 'Checks the Strict-Transport-Security header, which tells browsers to always use HTTPS and prevents SSL stripping attacks. max-age should be at least 180 days and includeSubDomains should cover subdomains. With preload, the requirements of the browser preload list (max-age of one year, includeSubDomains) are verified; the list itself is not queried.',
    remediation: <<<'TXT'
        Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
        Make sure all subdomains support HTTPS before adding includeSubDomains, then submit the domain at https://hstspreload.org/
        TXT,
    references: [
        'https://hstspreload.org/',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    ],
)]
final class StrictTransportSecurityRule implements RuleInterface
{
    private const int MIN_MAX_AGE = 15552000; // 180 days

    private const int PRELOAD_MAX_AGE = 31536000; // 1 year

    public function check(HttpResponseInterface $response): RuleStatus
    {
        if (!$response->isHttps()) {
            return RuleStatus::warning(
                rule: 'HSTS',
                message: 'Site is not served over HTTPS, HSTS cannot be applied',
            );
        }

        $header = $response->header('strict-transport-security');

        if ($header === null) {
            return RuleStatus::fail(
                rule: 'HSTS',
                message: 'Strict-Transport-Security header is missing',
            );
        }

        if (preg_match('~max-age\s*=\s*"?(\d+)~i', $header, $matches) !== 1) {
            return RuleStatus::fail(
                rule: 'HSTS',
                message: sprintf('Invalid header, max-age is missing: %s', $header),
            );
        }

        $maxAge = (int)$matches[1];
        $includeSubDomains = preg_match('~(^|;)\s*includesubdomains\s*(;|$)~i', $header) === 1;
        $preload = preg_match('~(^|;)\s*preload\s*(;|$)~i', $header) === 1;
        $warnings = [];

        if ($maxAge < self::MIN_MAX_AGE) {
            $warnings[] = sprintf('max-age=%d is too short, at least %d (180 days) is recommended', $maxAge, self::MIN_MAX_AGE);
        }

        if (!$includeSubDomains) {
            $warnings[] = 'includeSubDomains is missing, subdomains can be reached over HTTP and used to inject cookies';
        }

        // https://hstspreload.org/#submission-requirements
        if ($preload && ($maxAge < self::PRELOAD_MAX_AGE || !$includeSubDomains)) {
            $warnings[] = 'preload is requested, but the preload list requires max-age of at least 31536000 and includeSubDomains';
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'HSTS',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'HSTS',
            message: $preload
                ? sprintf('%s (submit the domain at hstspreload.org if it is not on the list yet)', $header)
                : sprintf('%s (consider preload, the first visit is not protected without it)', $header),
        );
    }
}
