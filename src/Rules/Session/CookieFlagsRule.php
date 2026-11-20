<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Session;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\SetCookie;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'session.cookie-flags-other',
    name: 'Cookie flags',
    category: 'Session',
    description: 'Checks the flags of all cookies other than the session cookie. Missing Secure lets the cookie travel over HTTP, missing HttpOnly makes it readable by JavaScript (XSS). SameSite=None without Secure and broken __Secure-/__Host- prefixes make browsers reject the cookie.',
    remediation: <<<'TXT'
        Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax; Path=/
        Leave out HttpOnly only for cookies that JavaScript really needs to read.
        __Host- cookies require Secure, Path=/ and no Domain attribute.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
    ],
)]
final class CookieFlagsRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $cookies = array_values(array_filter(
            $response->cookies(),
            static fn(SetCookie $cookie): bool => !$cookie->isSessionCookie() && !$cookie->isDeletion(),
        ));

        if ($cookies === []) {
            return RuleStatus::ok(
                rule: 'Cookie flags',
                message: 'No other cookies than the session cookie are set',
            );
        }

        $failures = [];
        $warnings = [];

        foreach ($cookies as $cookie) {
            $secure = $cookie->has('secure');
            $missing = [];

            if (!$secure) {
                $missing[] = 'Secure';
            }

            if (!$cookie->has('httponly')) {
                $missing[] = 'HttpOnly';
            }

            if ($missing !== []) {
                $warnings[] = sprintf('%s: missing %s', $cookie->name, implode(', ', $missing));
            }

            if (strtolower($cookie->get('samesite') ?? '') === 'none' && !$secure) {
                $failures[] = sprintf('%s: SameSite=None without Secure is rejected by browsers', $cookie->name);
            }

            if (str_starts_with($cookie->name, '__Secure-') && !$secure) {
                $failures[] = sprintf('%s: __Secure- prefix requires Secure', $cookie->name);
            }

            if (str_starts_with($cookie->name, '__Host-')
                && (!$secure || $cookie->has('domain') || $cookie->get('path') !== '/')) {
                $failures[] = sprintf('%s: __Host- prefix requires Secure, Path=/ and no Domain', $cookie->name);
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'Cookie flags',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Cookie flags',
                message: implode('; ', $warnings),
            );
        }

        $names = implode(', ', array_map(static fn(SetCookie $cookie): string => $cookie->name, $cookies));

        return RuleStatus::ok(
            rule: 'Cookie flags',
            message: sprintf('%s: Secure, HttpOnly', $names),
        );
    }
}
