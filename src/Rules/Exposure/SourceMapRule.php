<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.source-maps',
    name: 'Source maps',
    category: 'Exposure',
    description: 'Looks for publicly accessible source maps of same-origin scripts and stylesheets (SourceMap header, sourceMappingURL comment or a guessed file.js.map). Source maps contain the original frontend source code including comments, internal API endpoints and sometimes keys. A map is reported only when it is valid source map JSON.',
    remediation: <<<'TXT'
        Do not deploy *.map files, or upload them only to your error tracker:
        Vite: build.sourcemap = false (or 'hidden' without deploying the maps)
        webpack: devtool = false (or 'hidden-source-map')
        Next.js: productionBrowserSourceMaps: false
        nginx: location ~ \.map$ { deny all; }
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Glossary/Source_map',
        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
)]
final readonly class SourceMapRule implements RuleInterface
{
    private const int MAX_ASSETS = 10;

    /** The sourceMappingURL comment is at the end of the file, only its tail is kept. */
    private const int TAIL_BYTES = 4096;

    /** Assets larger than this are not read to the end, the map URL is guessed instead. */
    private const int MAX_ASSET_BYTES = 5 * 1024 * 1024;

    /** Only the beginning of each map is downloaded, enough to recognize its format. */
    private const int MAX_MAP_BYTES = 8192;

    private PageAssets $pageAssets;

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $xpath = $response->xpath();
        $assets = $xpath instanceof DOMXPath ? $this->pageAssets->scriptsAndStylesheets($xpath, $response->url(), self::MAX_ASSETS) : [];

        if ($assets === []) {
            return RuleStatus::ok(
                rule: 'Source maps',
                message: 'Page has no same-origin scripts or stylesheets to check',
            );
        }

        $found = [];
        $maps = [];

        foreach ($this->mapReferences($assets) as $asset => $reference) {
            if (str_starts_with(strtolower($reference), 'data:')) {
                if ($this->isInlineSourceMap($reference)) {
                    $found[] = sprintf('inline in %s', $asset);
                }

                continue;
            }

            $map = PageAssets::resolve($asset, $reference);

            if ($map !== null) {
                $maps[$map] = true;
            }
        }

        foreach ($this->pageAssets->download(array_keys($maps), self::MAX_MAP_BYTES) as $map => $content) {
            if ($this->isSourceMap($content)) {
                $found[] = $map;
            }
        }

        if ($found !== []) {
            return RuleStatus::fail(
                rule: 'Source maps',
                message: sprintf('Publicly accessible: %s', implode(', ', $found)),
            );
        }

        return RuleStatus::ok(
            rule: 'Source maps',
            message: sprintf('No source maps found for %d scripts and stylesheets', count($assets)),
        );
    }

    /**
     * Finds the source map reference of every asset: the SourceMap header, the sourceMappingURL
     * comment at the end of the file, or the guessed file.map next to it.
     *
     * @param list<string> $assets
     * @return array<string, string> asset URL => map reference (relative to the asset)
     */
    private function mapReferences(array $assets): array
    {
        $requests = [];

        foreach ($assets as $asset) {
            // ask only for the end of the file, servers without range support send all of it
            $requests[] = $this->httpClient->request('GET', $asset, [
                'timeout' => 10,
                'headers' => ['Range' => 'bytes=-' . self::TAIL_BYTES],
                'user_data' => $asset,
            ]);
        }

        $tails = [];
        $headers = [];
        $sizes = [];

        foreach ($this->httpClient->stream($requests) as $request => $chunk) {
            $asset = $request->getInfo('user_data');

            if (!is_string($asset)) {
                $request->cancel();
                continue;
            }

            try {
                if ($chunk->isFirst()) {
                    if (!in_array($request->getStatusCode(), [200, 206], true)) {
                        $request->cancel();
                        continue;
                    }

                    $responseHeaders = $request->getHeaders(false);
                    $headers[$asset] = $responseHeaders['sourcemap'][0] ?? $responseHeaders['x-sourcemap'][0] ?? null;
                    $tails[$asset] = '';
                    $sizes[$asset] = 0;
                }

                if (!isset($tails[$asset], $sizes[$asset]) || $sizes[$asset] > self::MAX_ASSET_BYTES) {
                    continue;
                }

                $content = $chunk->getContent();
                $sizes[$asset] += strlen($content);
                $tails[$asset] = substr($tails[$asset] . $content, -self::TAIL_BYTES);

                if ($sizes[$asset] > self::MAX_ASSET_BYTES) {
                    // the end of the file will not be read, the tail is not the real end
                    $tails[$asset] = '';
                    $request->cancel();
                }
            } catch (TransportExceptionInterface) {
                $request->cancel();
            }
        }

        $references = [];

        foreach ($tails as $asset => $tail) {
            $file = basename((string)parse_url($asset, PHP_URL_PATH));
            $reference = $headers[$asset] ?? $this->sourceMappingUrl($tail) ?? ($file !== '' ? $file . '.map' : null);

            if ($reference !== null) {
                $references[$asset] = $reference;
            }
        }

        return $references;
    }

    /**
     * The last sourceMappingURL comment, e.g. "//# sourceMappingURL=app.js.map" or "/*# sourceMappingURL=app.css.map *\/".
     */
    private function sourceMappingUrl(string $content): ?string
    {
        if (preg_match_all('~[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)~', $content, $matches) === 0) {
            return null;
        }

        $url = end($matches[1]);

        return is_string($url) && $url !== '' ? $url : null;
    }

    private function isSourceMap(string $content): bool
    {
        return preg_match('~^\s*(?:\)\]\}\'\s*)?\{~', $content) === 1
            && str_contains($content, '"version"')
            && (str_contains($content, '"sources"') || str_contains($content, '"sections"'));
    }

    /**
     * data:application/json;base64,… map embedded directly in the asset.
     */
    private function isInlineSourceMap(string $reference): bool
    {
        [$meta, $data] = array_pad(explode(',', $reference, 2), 2, '');
        $decoded = str_contains(strtolower($meta), ';base64') ? base64_decode($data, true) : rawurldecode($data);

        return is_string($decoded) && str_contains($decoded, '"sources"');
    }
}
