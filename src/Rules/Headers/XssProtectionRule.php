<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.xss-protection',
    name: 'X-XSS-Protection',
    category: 'Headers',
    description: 'Checks that the obsolete X-XSS-Protection header is missing or set to 0. The XSS auditor it turns on was removed from modern browsers because it could be abused to leak data from the page (XS-Leaks) or to disable legitimate scripts, and the report= parameter sends page content to the given URL. Protection against XSS is provided by Content-Security-Policy instead.',
    remediation: <<<'TXT'
        Remove the X-XSS-Protection header, or send:
        X-XSS-Protection: 0
        Protect against XSS with Content-Security-Policy and output encoding.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection',
    ],
)]
final class XssProtectionRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $value = $response->header('x-xss-protection');

        if ($value === null) {
            return RuleStatus::ok(
                rule: 'X-XSS-Protection',
                message: 'Header is not set, the obsolete XSS auditor is not requested',
            );
        }

        $parts = array_map(trim(...), explode(';', $value));
        $mode = $parts[0];

        if ($mode === '0') {
            return RuleStatus::ok(
                rule: 'X-XSS-Protection',
                message: 'X-XSS-Protection: 0 disables the obsolete XSS auditor',
            );
        }

        $issues = [sprintf('X-XSS-Protection: %s enables the obsolete XSS auditor, which can be abused for XS-Leaks; use 0 or remove the header', $value)];

        foreach (array_slice($parts, 1) as $parameter) {
            if (str_starts_with(strtolower($parameter), 'report=')) {
                $issues[] = sprintf('%s sends page content to an external URL', $parameter);
            }
        }

        return RuleStatus::warning(
            rule: 'X-XSS-Protection',
            message: implode('; ', $issues),
        );
    }
}
