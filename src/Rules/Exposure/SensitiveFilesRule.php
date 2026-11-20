<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[Rule(
    id: 'exposure.sensitive-files',
    name: 'Sensitive files',
    category: 'Exposure',
    description: 'Looks for commonly exposed files (version control metadata, .env, phpinfo, backups, database dumps, server status) that reveal source code, credentials or server configuration. A file is reported only when its content matches the expected format, so pages returning 200 for everything do not cause false positives.',
    remediation: "Remove the files from the web root and deny access to hidden files, e.g.\nnginx: location ~ /\\. { deny all; }\nApache: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>",
    references: [
        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
)]
final readonly class SensitiveFilesRule implements RuleInterface
{
    /** Only the beginning of each file is downloaded, enough to recognize its format. */
    private const int MAX_BYTES = 8192;

    /** path => expected content format */
    private const array FILES = [
        '/.git/HEAD' => 'git-head',
        '/.git/config' => 'git-config',
        '/.svn/wc.db' => 'sqlite',
        '/.env' => 'env',
        '/.env.local' => 'env',
        '/.env.production' => 'env',
        '/.htpasswd' => 'htpasswd',
        '/phpinfo.php' => 'phpinfo',
        '/info.php' => 'phpinfo',
        '/.DS_Store' => 'ds-store',
        '/server-status' => 'server-status',
        '/backup.zip' => 'zip',
        '/backup.tar.gz' => 'gzip',
        '/db.sql' => 'sql',
        '/dump.sql' => 'sql',
        '/database.sql' => 'sql',
        '/wp-config.php.bak' => 'php-source',
        '/config.php.bak' => 'php-source',
    ];

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = $this->origin($response->url());

        if ($origin === null) {
            return RuleStatus::warning(
                rule: 'Sensitive files',
                message: sprintf('Could not determine the target origin from %s', $response->url()),
            );
        }

        $requests = [];

        foreach (array_keys(self::FILES) as $path) {
            $requests[] = $this->httpClient->request('GET', $origin . $path, [
                'timeout' => 10,
                'max_redirects' => 0,
                'user_data' => $path,
            ]);
        }

        $found = [];

        foreach ($this->download($requests) as $path => $content) {
            if ($this->matches(self::FILES[$path], $content)) {
                $found[] = $path;
            }
        }

        if ($found !== []) {
            return RuleStatus::fail(
                rule: 'Sensitive files',
                message: sprintf('Publicly accessible: %s', implode(', ', $found)),
            );
        }

        return RuleStatus::ok(
            rule: 'Sensitive files',
            message: sprintf('None of %d commonly exposed files is accessible', count(self::FILES)),
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

    /**
     * Downloads the beginning of every 200 response concurrently, other responses are skipped.
     *
     * @param list<ResponseInterface> $requests
     * @return array<string, string> path => beginning of the content
     */
    private function download(array $requests): array
    {
        $contents = [];

        foreach ($this->httpClient->stream($requests) as $request => $chunk) {
            $path = $request->getInfo('user_data');

            if (!is_string($path)) {
                $request->cancel();
                continue;
            }

            try {
                if ($chunk->isFirst()) {
                    if ($request->getStatusCode() !== 200) {
                        $request->cancel();
                        continue;
                    }

                    $contents[$path] = '';
                }

                if (!isset($contents[$path])) {
                    continue;
                }

                $contents[$path] .= $chunk->getContent();

                if (strlen($contents[$path]) >= self::MAX_BYTES) {
                    $request->cancel();
                }
            } catch (TransportExceptionInterface) {
                // unreachable, timed out or canceled: keep what was downloaded so far
                $request->cancel();
            }
        }

        return $contents;
    }

    private function matches(string $format, string $content): bool
    {
        $isHtml = preg_match('~^\s*<(!doctype|html|head|body)~i', $content) === 1;

        return match ($format) {
            'git-head' => preg_match('~^(ref: refs/|[0-9a-f]{40}\s*$)~', $content) === 1,
            'git-config' => str_contains($content, '[core]'),
            'sqlite' => str_starts_with($content, "SQLite format 3\0"),
            'env' => !$isHtml && preg_match('~^[A-Z][A-Z0-9_]*\s*=~m', $content) === 1,
            'htpasswd' => !$isHtml && preg_match('~^[^:\s<]+:\S+$~m', $content) === 1,
            'phpinfo' => str_contains($content, 'phpinfo()') || preg_match('~PHP Version \d~', $content) === 1,
            'ds-store' => str_starts_with($content, "\x00\x00\x00\x01Bud1"),
            'server-status' => str_contains($content, 'Apache Server Status'),
            'zip' => str_starts_with($content, "PK\x03\x04"),
            'gzip' => str_starts_with($content, "\x1f\x8b"),
            'sql' => !$isHtml && preg_match('~(-- MySQL dump|PostgreSQL database dump|\bCREATE TABLE\b|\bINSERT INTO\b)~i', $content) === 1,
            'php-source' => str_contains($content, '<?php'),
            default => false,
        };
    }
}
