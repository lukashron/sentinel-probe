<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Api;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\Origin;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'api.documentation',
    name: 'API documentation',
    category: 'API',
    description: 'Looks for publicly accessible OpenAPI / Swagger specifications (/swagger.json, /openapi.json, /v3/api-docs, …) and documentation UIs (Swagger UI, ReDoc). They list every endpoint, parameter and data model including internal and admin operations, which makes finding vulnerable endpoints much easier. A file is reported only when its content is a specification or a documentation UI. Public documentation is fine for public APIs, the rule is a warning.',
    remediation: <<<'TXT'
        Disable the specification and the UI in production or put them behind authentication:
        Spring: springdoc.api-docs.enabled=false, springdoc.swagger-ui.enabled=false
        ASP.NET Core: call app.UseSwagger() / UseSwaggerUI() only in Development
        FastAPI: FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        NelmioApiDocBundle: restrict the routes to the dev environment or by firewall
        TXT,
    references: [
        'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
        'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
    ],
)]
final readonly class ApiDocumentationRule implements RuleInterface
{
    private const array PATHS = [
        '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml', '/api-docs', '/api-docs.json',
        '/v2/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json', '/api/swagger.json', '/api/openapi.json',
        '/swagger-ui.html', '/swagger-ui/', '/swagger/', '/api/docs', '/docs', '/redoc', '/api/doc',
    ];

    /** Only the beginning of each file is downloaded, enough to recognize its format. */
    private const int MAX_BYTES = 16384;

    private PageAssets $pageAssets;

    public function __construct(
        HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());

        if ($origin === null) {
            return RuleStatus::skip(
                rule: 'API documentation',
                message: sprintf('Could not determine the target origin from %s', $response->url()),
            );
        }

        $urls = array_map(static fn(string $path): string => $origin . $path, self::PATHS);
        $found = [];

        foreach ($this->pageAssets->download($urls, self::MAX_BYTES) as $url => $content) {
            $kind = $this->recognize($content);

            if ($kind !== null) {
                $found[] = sprintf('%s (%s)', (string)parse_url((string)$url, PHP_URL_PATH), $kind);
            }
        }

        if ($found !== []) {
            return RuleStatus::warning(
                rule: 'API documentation',
                message: sprintf('Publicly accessible: %s', implode(', ', $found)),
            );
        }

        return RuleStatus::ok(
            rule: 'API documentation',
            message: sprintf('None of %d common API documentation paths is accessible', count(self::PATHS)),
        );
    }

    private function recognize(string $content): ?string
    {
        if (preg_match('~^\s*\{.*"(swagger|openapi)"\s*:\s*"\d~s', $content) === 1
            || preg_match('~^\s*(swagger|openapi)\s*:\s*[\'"]?\d~m', $content) === 1) {
            return 'OpenAPI specification';
        }

        if (preg_match('~swagger-ui(-bundle|-standalone-preset|\.css)|id=["\']swagger-ui["\']~i', $content) === 1) {
            return 'Swagger UI';
        }

        if (preg_match('~<redoc[\s>]|redoc\.standalone\.js~i', $content) === 1) {
            return 'ReDoc';
        }

        return null;
    }
}
