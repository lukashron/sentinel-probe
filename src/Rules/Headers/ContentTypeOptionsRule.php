<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.content-type-options',
    name: 'X-Content-Type-Options',
    category: 'Headers',
    description: 'Checks the X-Content-Type-Options: nosniff header, which stops browsers from guessing (MIME-sniffing) the content type, e.g. executing an uploaded file as a script.',
    remediation: 'X-Content-Type-Options: nosniff',
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
    ],
)]
final class ContentTypeOptionsRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $header = $response->header('x-content-type-options');

        if ($header === null) {
            return RuleStatus::fail(
                rule: 'X-Content-Type-Options',
                message: 'Header is missing, browsers may MIME-sniff responses',
            );
        }

        if (strtolower($header) !== 'nosniff') {
            return RuleStatus::fail(
                rule: 'X-Content-Type-Options',
                message: sprintf('Invalid value "%s", expected nosniff', $header),
            );
        }

        return RuleStatus::ok(
            rule: 'X-Content-Type-Options',
            message: 'nosniff',
        );
    }
}
