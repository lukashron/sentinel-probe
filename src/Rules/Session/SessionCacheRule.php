<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Session;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'session.cache',
    name: 'Session cache',
    category: 'Session',
    description: 'When the page sets a session cookie, checks that Cache-Control prevents shared caches (proxies, CDNs) from storing it. A cached response with Set-Cookie can hand one visitor\'s session or personal data to other visitors.',
    remediation: <<<'TXT'
        Cache-Control: no-store
        PHP sends it by default with session.cache_limiter = nocache, do not change it to public.
        TXT,
    references: [
        'https://www.php.net/manual/en/function.session-cache-limiter.php',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
    ],
)]
final class SessionCacheRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
        if ($response->sessionCookies() === []) {
            return RuleStatus::ok(
                rule: 'Session cache',
                message: 'No session cookie is set on the target page, nothing to verify',
            );
        }

        $cacheControl = strtolower($response->headerLine('cache-control') ?? '');

        if ($cacheControl === '') {
            return RuleStatus::warning(
                rule: 'Session cache',
                message: 'Page sets a session cookie but has no Cache-Control header, caches may store it (session.cache_limiter)',
            );
        }

        if (str_contains($cacheControl, 'no-store')) {
            return RuleStatus::ok(
                rule: 'Session cache',
                message: sprintf('Cache-Control: %s', $cacheControl),
            );
        }

        if (str_contains($cacheControl, 'private')) {
            return RuleStatus::ok(
                rule: 'Session cache',
                message: sprintf('Cache-Control: %s, only the browser may store the page', $cacheControl),
            );
        }

        $sharedCacheable = str_contains($cacheControl, 'public')
            || str_contains($cacheControl, 's-maxage')
            || (preg_match('~max-age\s*=\s*(\d+)~', $cacheControl, $matches) === 1 && (int)$matches[1] > 0);

        if ($sharedCacheable) {
            return RuleStatus::fail(
                rule: 'Session cache',
                message: sprintf('Cache-Control: %s lets shared caches store the page together with the session cookie', $cacheControl),
            );
        }

        return RuleStatus::warning(
            rule: 'Session cache',
            message: sprintf('Cache-Control: %s does not forbid storing the page, use no-store', $cacheControl),
        );
    }
}
