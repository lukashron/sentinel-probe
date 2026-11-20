<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.referrer-policy',
    name: 'Referrer-Policy',
    category: 'Headers',
    description: 'Checks the Referrer-Policy header, which controls how much of the page URL is sent to other sites. Full URLs can leak tokens or personal data from query parameters.',
    remediation: 'Referrer-Policy: strict-origin-when-cross-origin',
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
    ],
)]
final class ReferrerPolicyRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $header = $response->headerLine('referrer-policy');

        if ($header === null) {
            return RuleStatus::warning(
                rule: 'Referrer-Policy',
                message: 'Header is missing, the browser default applies',
            );
        }

        // with a comma-separated fallback list, the last value supported by the browser wins
        $values = array_filter(array_map(trim(...), explode(',', strtolower($header))));
        $policy = (string)end($values);

        return match ($policy) {
            'unsafe-url' => RuleStatus::fail(
                rule: 'Referrer-Policy',
                message: 'unsafe-url sends the full URL (including query parameters) to every site',
            ),
            'no-referrer-when-downgrade' => RuleStatus::warning(
                rule: 'Referrer-Policy',
                message: 'no-referrer-when-downgrade sends the full URL to other sites, strict-origin-when-cross-origin is recommended',
            ),
            default => RuleStatus::ok(
                rule: 'Referrer-Policy',
                message: $policy,
            ),
        };
    }
}
