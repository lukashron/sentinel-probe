<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.clickjacking',
    name: 'Clickjacking',
    category: 'Headers',
    description: 'Checks that the page cannot be embedded in a frame on another site (X-Frame-Options or CSP frame-ancestors), which would let an attacker trick users into clicking hidden elements.',
    remediation: "Content-Security-Policy: frame-ancestors 'self'\nor for older browsers: X-Frame-Options: SAMEORIGIN",
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
    ],
)]
final class ClickjackingRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $policy = $response->header('content-security-policy');
        $frameAncestors = $policy === null ? null : (ContentSecurityPolicyRule::parse($policy)['frame-ancestors'] ?? null);

        if ($frameAncestors !== null) {
            if (preg_match('~(^|\s)\*(\s|$)~', $frameAncestors) === 1) {
                return RuleStatus::fail(
                    rule: 'Clickjacking',
                    message: 'CSP frame-ancestors * allows embedding from any site',
                );
            }

            return RuleStatus::ok(
                rule: 'Clickjacking',
                message: sprintf('CSP frame-ancestors %s', $frameAncestors),
            );
        }

        $frameOptions = $response->header('x-frame-options');

        if ($frameOptions === null) {
            return RuleStatus::fail(
                rule: 'Clickjacking',
                message: 'Neither X-Frame-Options nor CSP frame-ancestors is set',
            );
        }

        if (in_array(strtoupper($frameOptions), ['DENY', 'SAMEORIGIN'], true)) {
            return RuleStatus::ok(
                rule: 'Clickjacking',
                message: sprintf('X-Frame-Options: %s', $frameOptions),
            );
        }

        return RuleStatus::warning(
            rule: 'Clickjacking',
            message: sprintf('X-Frame-Options: %s is not supported by browsers, use DENY or SAMEORIGIN', $frameOptions),
        );
    }
}
