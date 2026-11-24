<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Domain;

use DateTimeImmutable;
use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\Origin;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'domain.security-txt',
    name: 'security.txt',
    category: 'Domain',
    description: 'Checks /.well-known/security.txt (RFC 9116), which tells security researchers how to report vulnerabilities. The file must be plain text served over HTTPS and contain the required Contact and Expires fields, Expires must be in the future. Without it, found vulnerabilities are often not reported at all or end up in public.',
    remediation: <<<'TXT'
        Create /.well-known/security.txt (Content-Type: text/plain):
        Contact: mailto:security@example.com
        Expires: 2027-12-31T23:00:00.000Z
        Preferred-Languages: en, cs
        Generator: https://securitytxt.org/
        TXT,
    references: [
        'https://www.rfc-editor.org/rfc/rfc9116',
        'https://securitytxt.org/',
    ],
)]
final readonly class SecurityTxtRule implements RuleInterface
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $origin = Origin::of($response->url());

        if ($origin === null) {
            return RuleStatus::skip(
                rule: 'security.txt',
                message: sprintf('Could not determine the target origin from %s', $response->url()),
            );
        }

        try {
            $requests = [
                '/.well-known/security.txt' => $this->httpClient->request('GET', $origin . '/.well-known/security.txt', ['timeout' => 10]),
                '/security.txt' => $this->httpClient->request('GET', $origin . '/security.txt', ['timeout' => 10]),
            ];

            $files = array_map(static fn($request): HttpResponse => new HttpResponse($request), $requests);
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'security.txt',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        foreach ($files as $path => $file) {
            if (!$file->isSuccessful() || $file->isHtml() || preg_match('~^\s*(Contact|Expires|Encryption|Policy|Canonical)\s*:~mi', $file->content()) !== 1) {
                continue;
            }

            $issues = $this->issues($file);

            if ($path === '/security.txt') {
                $issues[] = 'the file is at the legacy location /security.txt, move it to /.well-known/security.txt';
            }

            if ($issues !== []) {
                return RuleStatus::warning(
                    rule: 'security.txt',
                    message: sprintf('%s: %s', $path, implode('; ', $issues)),
                );
            }

            return RuleStatus::ok(
                rule: 'security.txt',
                message: sprintf('%s is valid', $path),
            );
        }

        return RuleStatus::warning(
            rule: 'security.txt',
            message: '/.well-known/security.txt is missing, researchers do not know how to report vulnerabilities',
        );
    }

    /**
     * @return list<string>
     */
    private function issues(HttpResponseInterface $file): array
    {
        $content = $file->content();
        $issues = [];

        if (!$file->isHttps()) {
            $issues[] = 'the file must be served over HTTPS';
        }

        if ($file->contentType() !== 'text/plain') {
            $issues[] = sprintf('Content-Type is %s, text/plain is required', $file->contentType() ?? 'missing');
        }

        if (preg_match('~^\s*Contact\s*:\s*\S+~mi', $content) !== 1) {
            $issues[] = 'the required Contact field is missing';
        }

        if (preg_match('~^\s*Expires\s*:\s*(\S+)~mi', $content, $match) !== 1) {
            $issues[] = 'the required Expires field is missing';
        } else {
            try {
                $expires = new DateTimeImmutable($match[1]);

                if ($expires < new DateTimeImmutable()) {
                    $issues[] = sprintf('the file expired on %s', $expires->format('Y-m-d'));
                }
            } catch (\Exception) {
                $issues[] = sprintf('Expires "%s" is not a valid ISO 8601 date', $match[1]);
            }
        }

        return $issues;
    }
}
