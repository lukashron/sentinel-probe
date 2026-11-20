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
    description: 'Checks for headers revealing the technology stack and its versions (X-Powered-By, Server, X-AspNet-Version), which helps attackers find known vulnerabilities.',
    remediation: "PHP: expose_php = Off (php.ini)\nnginx: server_tokens off;\nApache: ServerTokens Prod and ServerSignature Off",
    references: [
        'https://www.php.net/manual/en/ini.core.php#ini.expose-php',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
    ],
)]
final class InformationDisclosureRule implements RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus
    {
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

        foreach ($response->findHeaders('~^x-aspnet(mvc)?-version$~') as $name => $values) {
            $issues[] = sprintf('%s: %s', $name, implode(', ', $values));
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
