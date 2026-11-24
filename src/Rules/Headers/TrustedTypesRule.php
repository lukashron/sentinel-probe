<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.trusted-types',
    name: 'Trusted Types',
    category: 'Headers',
    description: "Checks that the Content-Security-Policy enforces Trusted Types (require-trusted-types-for 'script'). The browser then rejects plain strings passed to dangerous DOM sinks such as innerHTML, document.write or eval and accepts only values created by an approved policy, which blocks most DOM-based XSS. Warns about 'allow-duplicates' and the * wildcard in the trusted-types directive. Trusted Types are supported in Chromium-based browsers, so a missing directive is a warning only.",
    remediation: <<<'TXT'
        Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app-policy
        Roll it out with Content-Security-Policy-Report-Only first and fix the reported sinks.
        Create values for DOM sinks only through trustedTypes.createPolicy() with sanitization (e.g. DOMPurify).
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for',
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
    ],
)]
final class TrustedTypesRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $enforced = array_map(ContentSecurityPolicyRule::parse(...), $response->contentSecurityPolicies());

        if (!$this->requiresTrustedTypes($enforced)) {
            if ($this->requiresTrustedTypes(array_map(ContentSecurityPolicyRule::parse(...), $response->reportOnlyContentSecurityPolicies()))) {
                return RuleStatus::warning(
                    rule: 'Trusted Types',
                    message: 'Trusted Types are required only in Report-Only mode and are not enforced',
                );
            }

            return RuleStatus::warning(
                rule: 'Trusted Types',
                message: "Content-Security-Policy does not contain require-trusted-types-for 'script', DOM sinks accept plain strings",
            );
        }

        $names = [];
        $weaknesses = [];

        foreach ($enforced as $directives) {
            foreach (preg_split('~\s+~', $directives['trusted-types'] ?? '', -1, PREG_SPLIT_NO_EMPTY) ?: [] as $token) {
                $keyword = strtolower($token);

                if ($keyword === "'allow-duplicates'") {
                    $weaknesses[] = "'allow-duplicates' lets an attacker reuse an existing policy name";
                } elseif ($keyword === '*') {
                    $weaknesses[] = '* allows any policy name';
                } elseif ($keyword !== "'none'") {
                    $names[] = $token;
                }
            }
        }

        $message = $names === []
            ? "require-trusted-types-for 'script' is enforced"
            : sprintf("require-trusted-types-for 'script' is enforced, allowed policies: %s", implode(', ', array_unique($names)));

        if ($weaknesses !== []) {
            $message .= '; note: ' . implode('; ', array_unique($weaknesses));
        }

        return RuleStatus::ok(
            rule: 'Trusted Types',
            message: $message,
        );
    }

    /**
     * @param list<array<string, string>> $policies
     */
    private function requiresTrustedTypes(array $policies): bool
    {
        foreach ($policies as $directives) {
            if (preg_match("~(^|\s)'script'(\s|$)~i", $directives['require-trusted-types-for'] ?? '') === 1) {
                return true;
            }
        }

        return false;
    }
}
