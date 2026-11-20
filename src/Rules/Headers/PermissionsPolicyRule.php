<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.permissions-policy',
    name: 'Permissions-Policy',
    category: 'Headers',
    description: 'Checks the Permissions-Policy header, which disables browser features (camera, microphone, geolocation, …) the site does not need, limiting what injected or third-party code can do.',
    remediation: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
    ],
)]
final class PermissionsPolicyRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        if (!$response->hasHeader('permissions-policy')) {
            return RuleStatus::warning(
                rule: 'Permissions-Policy',
                message: 'Header is missing, browser features (camera, geolocation, …) are not restricted',
            );
        }

        return RuleStatus::ok(
            rule: 'Permissions-Policy',
            message: 'Browser features are restricted',
        );
    }
}
