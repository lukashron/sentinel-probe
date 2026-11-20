<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.debug-output',
    name: 'Debug output',
    category: 'Exposure',
    description: 'Looks for error messages, stack traces, SQL errors and debug tools (Tracy, Symfony profiler, PHP DebugBar, Whoops, Django, ASP.NET) on the target page and on a 404 page. They reveal file paths, source code, queries or configuration and indicate the application runs in debug mode.',
    remediation: <<<'TXT'
        PHP: display_errors = Off, log_errors = On (php.ini)
        Nette: run Tracy in production mode
        Symfony: APP_ENV=prod, APP_DEBUG=0
        Laravel: APP_ENV=production, APP_DEBUG=false
        TXT,
    references: [
        'https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors',
        'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
    ],
)]
final readonly class DebugOutputRule implements RuleInterface
{
    /** label => pattern */
    private const array PATTERNS = [
        'PHP error message' => '~(?:<b>)?(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:\s.{0,500}? on line (?:<b>)?\d+~is',
        'Uncaught exception' => '~Uncaught [\w\\\\]+(?:Exception|Error)\b~',
        'Stack trace' => '~Stack trace:\s*(?:<br\s*/?>)?\s*#0~i',
        'Java stack trace' => '~\bat (?:java|javax|org\.springframework)\.[\w.$]+\(~',
        'SQL error' => '~(?:You have an error in your SQL syntax|SQLSTATE\[\w+\]|ORA-\d{5}|PG::\w+Error|Unclosed quotation mark after the character string)~i',
        'Laravel exception' => '~Illuminate\\\\[A-Z]\w+\\\\~',
        'Tracy debugger' => '~id="tracy-(?:bs|debug)"~',
        'Symfony profiler' => '~(?:sf-toolbar|id="sfwdt|Symfony Profiler)~',
        'PHP DebugBar' => '~phpdebugbar~i',
        'Whoops error page' => '~class="Whoops container"~',
        'Django debug page' => '~DEBUG = True~',
        'ASP.NET error page' => "~Server Error in '/[^']*' Application~",
    ];

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $findings = [];

        foreach ($this->detect($response) as $label) {
            $findings[] = sprintf('%s on the target page', $label);
        }

        $notFound = $this->notFoundPage($response);

        if ($notFound !== null) {
            foreach ($this->detect($notFound) as $label) {
                $findings[] = sprintf('%s on the 404 page', $label);
            }
        }

        if ($findings !== []) {
            return RuleStatus::fail(
                rule: 'Debug output',
                message: implode('; ', $findings),
            );
        }

        return RuleStatus::ok(
            rule: 'Debug output',
            message: 'No error messages or debug tools found on the target and 404 page',
        );
    }

    /**
     * @return list<string> labels of the detected debug output
     */
    private function detect(HttpResponseInterface $response): array
    {
        $labels = [];

        foreach (self::PATTERNS as $label => $pattern) {
            if ($response->contentMatches($pattern)) {
                $labels[] = $label;
            }
        }

        return $labels;
    }

    /**
     * Requests a random non-existent page, error pages often show debug output.
     */
    private function notFoundPage(HttpResponseInterface $response): ?HttpResponseInterface
    {
        $scheme = $response->scheme();
        $host = $response->host();

        if ($scheme === null || $host === null) {
            return null;
        }

        $port = parse_url($response->url(), PHP_URL_PORT);
        $url = sprintf('%s://%s%s/sentinel-probe-%s', $scheme, $host, is_int($port) ? ':' . $port : '', bin2hex(random_bytes(8)));

        try {
            return new HttpResponse($this->httpClient->request('GET', $url, [
                'timeout' => 10,
                'max_redirects' => 0,
            ]));
        } catch (TransportExceptionInterface) {
            return null;
        }
    }
}
