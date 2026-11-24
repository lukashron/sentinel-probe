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
    description: 'Checks the session and authentication cookies (PHPSESSID, JSESSIONID, laravel_session, connect.sid, auth, token and JWT cookies, remember-me cookies, Supabase, Auth0, NextAuth, ASP.NET Identity). HttpOnly hides them from JavaScript (XSS), Secure sends them only over HTTPS and SameSite protects against CSRF; Lax is a good default, Strict is stricter but breaks logins coming from links on other sites. A Domain attribute shares the cookie with all subdomains, the __Host- prefix guarantees it is not shared.',
    remediation: <<<'TXT'
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1);
        ini_set('session.cookie_samesite', 'Lax'); // or 'Strict'
        Do not set the cookie Domain (session.cookie_domain) and consider the __Host- prefix, e.g. session_name('__Host-SID').
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
            return RuleStatus::skip(
                rule: 'Session cookie',
                message: 'No session or authentication cookie is set on the target page',
            );
        }

        $failures = [];
        $warnings = [];
        $notes = [];

        foreach ($cookies as $cookie) {
            if (!$cookie->has('httponly')) {
                $failures[] = sprintf('%s: missing HttpOnly (session.cookie_httponly)', $cookie->name);
            }

            if (!$cookie->has('secure')) {
                $failures[] = sprintf('%s: missing Secure (session.cookie_secure)', $cookie->name);
            }

            $sameSite = strtolower($cookie->get('samesite') ?? '');

            if ($sameSite === 'none') {
                $failures[] = sprintf('%s: SameSite=None allows cross-site requests (session.cookie_samesite)', $cookie->name);
            } elseif ($sameSite === 'lax') {
                $notes[] = sprintf('%s: SameSite=Lax, Strict also blocks top-level cross-site navigations', $cookie->name);
            } elseif ($sameSite !== 'strict') {
                $failures[] = sprintf('%s: missing SameSite (session.cookie_samesite)', $cookie->name);
            }

            $domain = $cookie->domain();

            if ($domain !== null) {
                $warnings[] = sprintf('%s: Domain=%s shares the cookie with all subdomains of %s, leave Domain out (session.cookie_domain)', $cookie->name, $domain, $domain);
            } elseif (!str_starts_with($cookie->name, '__Host-')) {
                $notes[] = sprintf('%s: consider the __Host- prefix', $cookie->name);
            }
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

        $names = implode(', ', array_map(static fn(SetCookie $cookie): string => $cookie->name, $cookies));

        return RuleStatus::ok(
            rule: 'Session cookie',
            message: sprintf('%s: HttpOnly, Secure, SameSite', $names) . ($notes !== [] ? '; note: ' . implode('; ', $notes) : ''),
        );
    }
}
