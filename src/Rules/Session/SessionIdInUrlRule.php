<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Session;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\SetCookie;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'session.id-in-url',
    name: 'Session ID in URL',
    category: 'Session',
    description: 'Checks that the session ID is not passed in the URL, page links or forms. A session ID in the URL leaks through browser history, logs and the Referer header and enables session hijacking.',
    remediation: <<<'TXT'
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_trans_sid', 0);
        TXT,
    references: [
        'https://www.php.net/manual/en/session.security.ini.php',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
    ],
)]
final class SessionIdInUrlRule implements RuleInterface
{
    private const array DEFAULT_NAMES = ['PHPSESSID', 'JSESSIONID'];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $names = array_unique([
            ...self::DEFAULT_NAMES,
            ...array_map(static fn(SetCookie $cookie): string => $cookie->name, $response->sessionCookies()),
        ]);

        $alternatives = implode('|', array_map(static fn(string $name): string => preg_quote($name, '~'), $names));

        $inQuery = '~[?&;](?:' . $alternatives . ')=[^&\s"\'<>#]+~i';
        $inForm = '~<input[^>]+name\s*=\s*["\']?(?:' . $alternatives . ')["\'\s/>]~i';

        if (preg_match($inQuery, $response->url()) === 1) {
            return RuleStatus::fail(
                rule: 'Session ID in URL',
                message: sprintf('Session ID is passed in the URL: %s (session.use_only_cookies)', $response->url()),
            );
        }

        if ($response->contentMatches($inQuery)) {
            return RuleStatus::fail(
                rule: 'Session ID in URL',
                message: 'Page links contain the session ID (session.use_only_cookies, session.use_trans_sid)',
            );
        }

        if ($response->contentMatches($inForm)) {
            return RuleStatus::fail(
                rule: 'Session ID in URL',
                message: 'Page forms contain the session ID (session.use_only_cookies, session.use_trans_sid)',
            );
        }

        return RuleStatus::ok(
            rule: 'Session ID in URL',
            message: 'Session ID is not exposed in URLs or forms',
        );
    }
}
