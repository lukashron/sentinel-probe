<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Transport;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'transport.https',
    name: 'HTTPS',
    category: 'Transport',
    description: 'Checks that the target (after redirects) is served over HTTPS, so traffic is encrypted and cannot be read or modified in transit.',
    remediation: 'Serve the site over HTTPS with a valid TLS certificate and redirect all HTTP requests to HTTPS (301).',
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
    ],
)]
final class HttpsRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        if (!$response->isHttps()) {
            return RuleStatus::fail(
                rule: 'HTTPS',
                message: sprintf('Communication is not encrypted: %s', $response->url()),
            );
        }

        return RuleStatus::ok(
            rule: 'HTTPS',
            message: sprintf('Communication runs over HTTPS: %s', $response->url()),
        );
    }
}
