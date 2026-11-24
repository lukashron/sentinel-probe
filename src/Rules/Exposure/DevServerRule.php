<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.dev-server',
    name: 'Dev server',
    category: 'Exposure',
    description: 'Detects frontend development servers running in production: Vite (also used by Nuxt, SvelteKit, Astro and Angular), webpack-dev-server and webpack-hot-middleware, Next.js in development mode and React Refresh. The page is searched for their client scripts and a few endpoints are probed (/@vite/client, /__webpack_hmr, /_next/webpack-hmr). A dev server serves unminified source files, hot module replacement and detailed error overlays, and Vite can additionally expose files outside the project through /@fs/.',
    remediation: <<<'TXT'
        Build the application for production and serve only the build output:
        Vite: vite build (then vite preview or any static server), Next.js: next build && next start, webpack: mode: 'production'.
        Never expose ports of vite / next dev / webpack serve to the internet, bind them to localhost.
        TXT,
    references: [
        'https://vite.dev/guide/build',
        'https://vite.dev/config/server-options#server-fs-allow',
        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
)]
final readonly class DevServerRule implements RuleInterface
{
    /** Marker in the page => detected dev server */
    private const array PAGE_MARKERS = [
        '~/@vite/client~' => 'Vite client script',
        '~/@react-refresh~' => 'React Refresh (Vite dev)',
        '~/@ng/component~' => 'Angular dev server (ng serve)',
        '~webpack-dev-server|webpackHotUpdate|__webpack_hmr~' => 'webpack dev server / HMR',
        '~/_next/static/development/|"buildId"\s*:\s*"development"~' => 'Next.js development mode',
    ];

    /** Probed path => [expected content pattern or null for an event stream, detected dev server] */
    private const array PROBES = [
        '/@vite/client' => ['~import\.meta\.hot|createHotContext~', 'Vite dev server (/@vite/client)'],
        '/__webpack_hmr' => [null, 'webpack-hot-middleware (/__webpack_hmr)'],
        '/_next/webpack-hmr' => [null, 'Next.js dev server (/_next/webpack-hmr)'],
    ];

    /** The client script is read only partially, HMR endpoints never end */
    private const int MAX_PROBE_BYTES = 64 * 1024;

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $found = [];

        foreach (self::PAGE_MARKERS as $pattern => $label) {
            if ($response->contentMatches($pattern)) {
                $found[] = sprintf('%s referenced by the page', $label);
            }
        }

        $origin = $this->origin($response->url());

        if ($origin !== null) {
            foreach ($this->probe($origin) as $label) {
                $found[] = $label;
            }
        }

        if ($found !== []) {
            return RuleStatus::fail(
                rule: 'Dev server',
                message: sprintf('Development server is running: %s', implode('; ', array_unique($found))),
            );
        }

        return RuleStatus::ok(
            rule: 'Dev server',
            message: sprintf('No development server markers on the page and on %d dev endpoints', count(self::PROBES)),
        );
    }

    /**
     * @return list<string> detected dev servers
     */
    private function probe(string $origin): array
    {
        $requests = [];

        foreach (array_keys(self::PROBES) as $path) {
            $requests[$path] = $this->httpClient->request('GET', $origin . $path, [
                'timeout' => 10,
                'max_duration' => 10,
                'max_redirects' => 0,
                'user_data' => $path,
            ]);
        }

        $found = [];
        $contents = [];

        foreach ($this->httpClient->stream($requests) as $request => $chunk) {
            $path = $request->getInfo('user_data');

            if (!is_string($path) || !isset(self::PROBES[$path])) {
                $request->cancel();
                continue;
            }

            [$pattern, $label] = self::PROBES[$path];

            try {
                if ($chunk->isFirst()) {
                    if ($request->getStatusCode() !== 200) {
                        $request->cancel();
                        continue;
                    }

                    if ($pattern === null) {
                        // HMR endpoints are endless event streams, the content type is enough
                        $contentType = $request->getHeaders(false)['content-type'][0] ?? '';

                        if (str_starts_with(strtolower($contentType), 'text/event-stream')) {
                            $found[] = $label;
                        }

                        $request->cancel();
                        continue;
                    }

                    $contents[$path] = '';
                }

                if (!isset($contents[$path])) {
                    continue;
                }

                $contents[$path] .= $chunk->getContent();

                if (preg_match($pattern, $contents[$path]) === 1) {
                    $found[] = $label;
                    unset($contents[$path]);
                    $request->cancel();
                } elseif (strlen($contents[$path]) >= self::MAX_PROBE_BYTES) {
                    unset($contents[$path]);
                    $request->cancel();
                }
            } catch (ExceptionInterface) {
                // unreachable, timed out or canceled
                $request->cancel();
            }
        }

        return $found;
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
