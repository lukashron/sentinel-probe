<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Api;

use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\Origin;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'api.http-methods',
    name: 'HTTP methods',
    category: 'API',
    description: 'Asks the target page and a static file of the page with OPTIONS which methods they allow and reports methods that modify files (PUT, DELETE, PATCH on static files) and WebDAV methods (PROPFIND, MKCOL, COPY, MOVE, LOCK, …). Sends a PROPFIND request to detect enabled WebDAV, which can list and often modify files. Only read-only requests are sent, PUT and DELETE are never tried.',
    remediation: <<<'TXT'
        Allow only the methods the application needs, e.g.
        nginx: if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }  (per location for static files)
        Apache: <LimitExcept GET POST HEAD> Require all denied </LimitExcept>
        Disable WebDAV modules (nginx dav_methods, Apache mod_dav, IIS WebDAV Publishing) when they are not needed.
        TXT,
    references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
    ],
)]
final readonly class HttpMethodsRule implements RuleInterface
{
    private const array WEBDAV_METHODS = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'SEARCH'];

    /** Methods that modify a static file */
    private const array WRITE_METHODS = ['PUT', 'DELETE', 'PATCH'];

    private PageAssets $pageAssets;

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());

        if ($origin === null) {
            return RuleStatus::skip(
                rule: 'HTTP methods',
                message: sprintf('Could not determine the target origin from %s', $response->url()),
            );
        }

        $xpath = $response->xpath();
        $staticFile = $xpath instanceof DOMXPath ? ($this->pageAssets->scriptsAndStylesheets($xpath, $response->url(), 1)[0] ?? null) : null;

        $targets = ['the page' => $response->url()];

        if ($staticFile !== null) {
            $targets[sprintf('static file %s', (string)parse_url($staticFile, PHP_URL_PATH))] = $staticFile;
        }

        try {
            $requests = [];

            foreach ($targets as $label => $url) {
                $requests[$label] = $this->httpClient->request('OPTIONS', $url, ['timeout' => 10, 'max_redirects' => 0]);
            }

            $propfind = $this->httpClient->request('PROPFIND', $origin . '/', [
                'timeout' => 10,
                'max_redirects' => 0,
                'headers' => ['Depth' => '0', 'Content-Type' => 'application/xml'],
                'body' => '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>',
            ]);

            $options = array_map(static fn($request): HttpResponse => new HttpResponse($request), $requests);
            $propfindResponse = new HttpResponse($propfind);
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'HTTP methods',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        $failures = [];
        $warnings = [];

        if ($propfindResponse->statusCode() === 207 && $propfindResponse->contentMatches('~multistatus~i')) {
            $failures[] = 'WebDAV is enabled, PROPFIND / returned 207 Multi-Status';
        }

        foreach ($options as $label => $probe) {
            $allowed = $this->allowedMethods($probe);
            $isStatic = $label !== 'the page';

            $webdav = array_values(array_intersect($allowed, self::WEBDAV_METHODS));
            $write = array_values(array_intersect($allowed, $isStatic ? self::WRITE_METHODS : ['PUT', 'DELETE']));

            if ($webdav !== []) {
                $warnings[] = sprintf('%s allows WebDAV methods %s', $label, implode(', ', $webdav));
            }

            if ($write !== []) {
                $warnings[] = sprintf('%s allows %s according to the Allow header', $label, implode(', ', $write));
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'HTTP methods',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'HTTP methods',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'HTTP methods',
            message: sprintf('No WebDAV or file modifying methods are allowed on %s', implode(' and ', array_keys($targets))),
        );
    }

    /**
     * @return list<string> uppercase methods from the Allow header
     */
    private function allowedMethods(HttpResponseInterface $response): array
    {
        $allow = $response->headerLine('allow') ?? '';

        return array_values(array_filter(array_map(
            static fn(string $method): string => strtoupper(trim($method)),
            explode(',', $allow),
        )));
    }
}
