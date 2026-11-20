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
    description: 'Checks the Strict-Transport-Security header, which tells browsers to always use HTTPS and prevents SSL stripping attacks. max-age should be at least 180 days.',
    remediation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    ],
)]
final class StrictTransportSecurityRule implements RuleInterface
{
    private const int MIN_MAX_AGE = 15552000; // 180 days

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

        if ((int)$matches[1] < self::MIN_MAX_AGE) {
            return RuleStatus::warning(
                rule: 'HSTS',
                message: sprintf('max-age=%s is too short, at least %d (180 days) is recommended', $matches[1], self::MIN_MAX_AGE),
            );
        }

        return RuleStatus::ok(
            rule: 'HSTS',
            message: $header,
        );
    }
}
