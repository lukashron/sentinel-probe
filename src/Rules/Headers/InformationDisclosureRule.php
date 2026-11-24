<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'headers.information-disclosure',
    name: 'Information disclosure',
    category: 'Headers',
    description: 'Checks for headers revealing the technology stack, its versions and internals (X-Powered-By, Server, X-AspNet-Version, X-Generator, X-Drupal-*, X-Runtime, Via, Server-Timing), which helps attackers find known vulnerabilities. X-Debug-Token and X-Debug-Token-Link mean the Symfony profiler is enabled in production, which exposes requests of all visitors including cookies, environment variables and database queries.',
    remediation: <<<'TXT'
        PHP: expose_php = Off (php.ini)
        nginx: server_tokens off; and proxy_hide_header for X-Generator, X-Drupal-*, X-Runtime
        Apache: ServerTokens Prod and ServerSignature Off
        Symfony: run production with APP_ENV=prod and APP_DEBUG=0, never install the web profiler there
        Send Server-Timing only to trusted clients and Via only inside your infrastructure.
        TXT,
    references: [
        'https://www.php.net/manual/en/ini.core.php#ini.expose-php',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
        'https://symfony.com/doc/current/profiler.html',
    ],
)]
final class InformationDisclosureRule implements RuleInterface
{
    /** Header name pattern => what it reveals */
    private const array REVEALING_HEADERS = [
        '~^x-aspnet(mvc)?-version$~' => 'ASP.NET version',
        '~^x-generator$~' => 'CMS or generator',
        '~^x-drupal-~' => 'Drupal',
        '~^x-runtime$~' => 'Ruby on Rails request timing',
        '~^via$~' => 'proxies and their versions',
        '~^server-timing$~' => 'internal timing of the backend (database, cache, …)',
    ];

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $debugToken = $response->header('x-debug-token-link') ?? $response->header('x-debug-token');

        if ($debugToken !== null) {
            return RuleStatus::fail(
                rule: 'Information disclosure',
                message: sprintf('Symfony profiler is enabled in production (X-Debug-Token: %s), it exposes requests of all visitors, cookies, environment variables and SQL queries', $debugToken),
            );
        }

        $issues = [];

        $poweredBy = $response->header('x-powered-by');

        if ($poweredBy !== null) {
            $hint = $response->headerContains('x-powered-by', 'php') ? ' (set expose_php = Off)' : '';
            $issues[] = sprintf('X-Powered-By: %s%s', $poweredBy, $hint);
        }

        $server = $response->header('server');

        if ($server !== null && preg_match('~\d~', $server) === 1) {
            $issues[] = sprintf('Server: %s reveals the version', $server);
        }

        foreach (self::REVEALING_HEADERS as $pattern => $reveals) {
            foreach ($response->findHeaders($pattern) as $name => $values) {
                $issues[] = sprintf('%s: %s reveals %s', $name, implode(', ', $values), $reveals);
            }
        }

        if ($issues !== []) {
            return RuleStatus::warning(
                rule: 'Information disclosure',
                message: implode('; ', $issues),
            );
        }

        return RuleStatus::ok(
            rule: 'Information disclosure',
            message: 'No technology versions disclosed in headers',
        );
    }
}
