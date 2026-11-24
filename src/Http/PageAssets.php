<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Http;

use DOMXPath;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Finds scripts and stylesheets referenced by a page and downloads them.
 */
final readonly class PageAssets
{
    private const string SCRIPTS = '//script[@src]/@src';

    private const string STYLESHEETS = '//link[contains(concat(" ", normalize-space(@rel), " "), " stylesheet ")]/@href';

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    /**
     * Absolute URLs of same-origin scripts on the page.
     *
     * @return list<string>
     */
    public function scripts(DOMXPath $xpath, string $pageUrl, int $limit): array
    {
        return $this->find($xpath, $pageUrl, [self::SCRIPTS], $limit);
    }

    /**
     * Absolute URLs of same-origin scripts and stylesheets on the page.
     *
     * @return list<string>
     */
    public function scriptsAndStylesheets(DOMXPath $xpath, string $pageUrl, int $limit): array
    {
        return $this->find($xpath, $pageUrl, [self::SCRIPTS, self::STYLESHEETS], $limit);
    }

    /**
     * Downloads the beginning of every 200 response concurrently, other responses are skipped.
     *
     * @param list<string> $urls
     * @return array<string, string> URL => beginning of the content (at most $maxBytes, a little more for the last chunk)
     */
    public function download(array $urls, int $maxBytes): array
    {
        $requests = [];

        foreach ($urls as $url) {
            $requests[] = $this->httpClient->request('GET', $url, [
                'timeout' => 10,
                'max_redirects' => 0,
                'user_data' => $url,
            ]);
        }

        $contents = [];

        foreach ($this->httpClient->stream($requests) as $request => $chunk) {
            $url = $request->getInfo('user_data');

            if (!is_string($url)) {
                $request->cancel();
                continue;
            }

            try {
                if ($chunk->isFirst()) {
                    if ($request->getStatusCode() !== 200) {
                        $request->cancel();
                        continue;
                    }

                    $contents[$url] = '';
                }

                if (!isset($contents[$url])) {
                    continue;
                }

                $contents[$url] .= $chunk->getContent();

                if (strlen($contents[$url]) >= $maxBytes) {
                    $request->cancel();
                }
            } catch (TransportExceptionInterface) {
                // unreachable, timed out or canceled: keep what was downloaded so far
                $request->cancel();
            }
        }

        return $contents;
    }

    /**
     * Resolves a reference (absolute, protocol-relative, root-relative or relative) against a base URL.
     * Returns null for empty references and non-HTTP schemes (data:, javascript:, …).
     */
    public static function resolve(string $base, string $reference): ?string
    {
        $reference = explode('#', trim($reference), 2)[0];

        if ($reference === '') {
            return null;
        }

        if (preg_match('~^[a-z][a-z0-9+.-]*:~i', $reference) === 1) {
            return preg_match('~^https?://~i', $reference) === 1 ? $reference : null;
        }

        $parts = parse_url($base);

        if (!isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        if (str_starts_with($reference, '//')) {
            return $parts['scheme'] . ':' . $reference;
        }

        $origin = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $basePath = $parts['path'] ?? '/';

        $path = match (true) {
            str_starts_with($reference, '/') => $reference,
            str_starts_with($reference, '?') => $basePath . $reference,
            default => (preg_replace('~/[^/]*$~', '/', $basePath) ?? '/') . $reference,
        };

        [$path, $query] = array_pad(explode('?', $path, 2), 2, null);
        $segments = [];

        foreach (explode('/', $path ?? '') as $segment) {
            if ($segment === '.') {
                continue;
            }

            if ($segment === '..') {
                // keep the leading empty segment of the absolute path
                if (count($segments) > 1) {
                    array_pop($segments);
                }

                continue;
            }

            $segments[] = $segment;
        }

        return $origin . implode('/', $segments) . ($query !== null ? '?' . $query : '');
    }

    /**
     * @param list<string> $queries XPath queries selecting URL attributes
     * @return list<string>
     */
    private function find(DOMXPath $xpath, string $pageUrl, array $queries, int $limit): array
    {
        $host = parse_url($pageUrl, PHP_URL_HOST);

        if (!is_string($host)) {
            return [];
        }

        $assets = [];

        foreach ($queries as $query) {
            foreach ($xpath->query($query) ?: [] as $attribute) {
                $url = self::resolve($pageUrl, (string)$attribute->nodeValue);

                if ($url !== null && strcasecmp((string)parse_url($url, PHP_URL_HOST), $host) === 0) {
                    $assets[$url] = true;
                }
            }
        }

        return array_slice(array_keys($assets), 0, $limit);
    }
}
