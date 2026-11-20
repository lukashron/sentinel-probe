<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Session;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\SetCookie;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'session.cookie-flags',
    name: 'Session cookie',
    category: 'Session',
    description: 'Checks the HttpOnly, Secure and SameSite flags of the session cookie. HttpOnly hides it from JavaScript (XSS), Secure sends it only over HTTPS and SameSite=Strict protects against CSRF.',
    remediation: <<<'TXT'
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1);
        ini_set('session.cookie_samesite', 'Strict');
        TXT,
    references: [
        'https://www.php.net/manual/en/session.security.ini.php',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
    ],
)]
final class SessionCookieRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        $cookies = $response->sessionCookies();

        if ($cookies === []) {
            return RuleStatus::ok(
                rule: 'Session cookie',
                message: 'No session cookie is set on the target page',
            );
        }

        $failures = [];
        $warnings = [];

        foreach ($cookies as $cookie) {
            if (!$cookie->has('httponly')) {
                $failures[] = sprintf('%s: missing HttpOnly (session.cookie_httponly)', $cookie->name);
            }

            if (!$cookie->has('secure')) {
                $failures[] = sprintf('%s: missing Secure (session.cookie_secure)', $cookie->name);
            }

            $sameSite = strtolower($cookie->get('samesite') ?? '');

            match ($sameSite) {
                'strict' => null,
                'lax' => $warnings[] = sprintf('%s: SameSite=Lax, Strict is recommended (session.cookie_samesite)', $cookie->name),
                'none' => $failures[] = sprintf('%s: SameSite=None allows cross-site requests (session.cookie_samesite)', $cookie->name),
                default => $failures[] = sprintf('%s: missing SameSite (session.cookie_samesite)', $cookie->name),
            };
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'Session cookie',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Session cookie',
                message: implode('; ', $warnings),
            );
        }

        $names = implode(', ', array_map(static fn(SetCookie $cookie) => $cookie->name, $cookies));

        return RuleStatus::ok(
            rule: 'Session cookie',
            message: sprintf('%s: HttpOnly, Secure, SameSite=Strict', $names),
        );
    }
}
