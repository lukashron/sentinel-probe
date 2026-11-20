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
    id: 'exposure.directory-listing',
    name: 'Directory listing',
    category: 'Exposure',
    description: 'Checks the target page and common directories (uploads, assets, backup, …) for automatically generated directory listings (Apache, nginx, IIS, Tomcat, Python). A listing reveals every file in the directory, including ones not linked from the site.',
    remediation: <<<'TXT'
        nginx: autoindex off;
        Apache: Options -Indexes
        IIS: <directoryBrowse enabled="false" />
        TXT,
    references: [
        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
)]
final readonly class DirectoryListingRule implements RuleInterface
{
    private const array DIRECTORIES = [
        '/assets/', '/backup/', '/css/', '/files/', '/images/', '/img/',
        '/js/', '/media/', '/static/', '/tmp/', '/upload/', '/uploads/',
    ];

    private const string PATTERN = '~(<title>\s*(?:Index of /|Directory listing for /)|\[To Parent Directory]|Directory Listing For /)~i';

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $found = [];

        if ($response->contentMatches(self::PATTERN)) {
            $found[] = (string)parse_url($response->url(), PHP_URL_PATH) ?: '/';
        }

        $origin = $this->origin($response->url());

        if ($origin !== null) {
            // requests run concurrently, they are read one by one afterwards
            $requests = [];

            foreach (self::DIRECTORIES as $directory) {
                $requests[$directory] = $this->httpClient->request('GET', $origin . $directory, [
                    'timeout' => 10,
                    'max_redirects' => 0,
                ]);
            }

            foreach ($requests as $directory => $request) {
                try {
                    $probe = new HttpResponse($request);
                } catch (TransportExceptionInterface) {
                    continue;
                }

                if ($probe->statusCode() === 200 && $probe->contentMatches(self::PATTERN)) {
                    $found[] = $directory;
                }
            }
        }

        if ($found !== []) {
            return RuleStatus::fail(
                rule: 'Directory listing',
                message: sprintf('Directory listing is enabled: %s', implode(', ', array_unique($found))),
            );
        }

        return RuleStatus::ok(
            rule: 'Directory listing',
            message: sprintf('No directory listing on the target page and %d common directories', count(self::DIRECTORIES)),
        );
    }

    /**
     * scheme://host[:port] of the target.
     */
    private function origin(string $url): ?string
    {
        $parts = parse_url($url);

        if (!isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        return $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
