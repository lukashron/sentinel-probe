<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Session;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'session.strict-mode',
    name: 'Session strict mode',
    category: 'Session',
    description: 'Sends a second request with a made-up session ID and checks that the server rejects it and issues a new one. Accepting uninitialized session IDs enables session fixation attacks.',
    remediation: <<<'TXT'
        ini_set('session.use_strict_mode', 1);
        Also call session_regenerate_id(true) after login.
        TXT,
    references: [
        'https://www.php.net/manual/en/session.configuration.php#ini.session.use-strict-mode',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
    ],
)]
final readonly class SessionStrictModeRule implements RuleInterface
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $cookies = $response->sessionCookies();

        if ($cookies === []) {
            return RuleStatus::ok(
                rule: 'Session strict mode',
                message: 'No session cookie is set on the target page, nothing to verify',
            );
        }

        $name = $cookies[0]->name;
        $fakeId = bin2hex(random_bytes(16));

        try {
            $probe = new HttpResponse($this->httpClient->request('GET', $response->url(), [
                'timeout' => 10,
                'headers' => ['Cookie' => $name . '=' . $fakeId],
            ]));
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'Session strict mode',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        $issued = $probe->cookie($name);

        if ($issued === null || $issued->isDeletion()) {
            return RuleStatus::warning(
                rule: 'Session strict mode',
                message: sprintf('%s: server did not replace an uninitialized session ID, strict mode is probably disabled (session.use_strict_mode)', $name),
            );
        }

        if ($issued->value === $fakeId) {
            return RuleStatus::fail(
                rule: 'Session strict mode',
                message: sprintf('%s: server accepted an uninitialized session ID, session fixation is possible (session.use_strict_mode)', $name),
            );
        }

        return RuleStatus::ok(
            rule: 'Session strict mode',
            message: sprintf('%s: uninitialized session ID was rejected and replaced', $name),
        );
    }
}
