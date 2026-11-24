<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Http;

use DOMDocument;
use DOMXPath;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

final readonly class HttpResponse implements HttpResponseInterface
{
    private string $url;

    private int $statusCode;

    private string $content;

    /** @var array<string, list<string>> */
    private array $headers;

    /**
     * Reads the whole response without throwing on 3xx/4xx/5xx status codes.
     *
     * @throws TransportExceptionInterface when the target is unreachable
     */
    public function __construct(ResponseInterface $response)
    {
        $url = $response->getInfo('url');
        $this->url = is_string($url) ? $url : '';
        $this->statusCode = $response->getStatusCode();
        $this->content = $response->getContent(false);

        $headers = [];

        foreach ($response->getHeaders(false) as $name => $values) {
            $key = strtolower((string)$name);
            $headers[$key] = [...($headers[$key] ?? []), ...$values];
        }

        $this->headers = $headers;
    }

    # ====================================
    #   URL / HTTP
    # ====================================

    public function url(): string
    {
        return $this->url;
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }

    public function scheme(): ?string
    {
        $scheme = parse_url($this->url, PHP_URL_SCHEME);

        return is_string($scheme) ? strtolower($scheme) : null;
    }

    public function host(): ?string
    {
        $host = parse_url($this->url, PHP_URL_HOST);

        return is_string($host) ? strtolower($host) : null;
    }

    public function isHttps(): bool
    {
        return $this->scheme() === 'https';
    }

    public function isSuccessful(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    public function isClientError(): bool
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }

    public function isServerError(): bool
    {
        return $this->statusCode >= 500;
    }

    # ====================================
    #   Headers
    # ====================================

    public function headers(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[strtolower($name)]);
    }

    public function header(string $name): ?string
    {
        $values = $this->headerValues($name);

        return $values === [] ? null : trim($values[0]);
    }

    public function headerValues(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function headerLine(string $name): ?string
    {
        $values = $this->headerValues($name);

        return $values === [] ? null : implode(', ', array_map(trim(...), $values));
    }

    public function headerContains(string $name, string $needle): bool
    {
        $line = $this->headerLine($name);

        return $line !== null && stripos($line, $needle) !== false;
    }

    public function findHeaders(string $pattern): array
    {
        return array_filter(
            $this->headers,
            static fn(string $name): bool => preg_match($pattern, $name) === 1,
            ARRAY_FILTER_USE_KEY,
        );
    }

    public function contentSecurityPolicies(bool $headersOnly = false): array
    {
        $policies = $this->splitPolicies($this->headerValues('content-security-policy'));

        if ($headersOnly || !$this->isHtml()) {
            return $policies;
        }

        $xpath = $this->xpath();
        $query = '//meta[translate(@http-equiv, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz") = "content-security-policy"]/@content';
        $meta = [];

        foreach ($xpath?->query($query) ?: [] as $attribute) {
            $meta[] = (string)$attribute->nodeValue;
        }

        return [...$policies, ...$this->splitPolicies($meta)];
    }

    public function reportOnlyContentSecurityPolicies(): array
    {
        return $this->splitPolicies($this->headerValues('content-security-policy-report-only'));
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function splitPolicies(array $values): array
    {
        $policies = [];

        foreach ($values as $value) {
            foreach (explode(',', $value) as $policy) {
                if (trim($policy) !== '') {
                    $policies[] = trim($policy);
                }
            }
        }

        return $policies;
    }

    # ====================================
    #   Content
    # ====================================

    public function content(): string
    {
        return $this->content;
    }

    public function contentType(): ?string
    {
        $header = $this->header('content-type');

        return $header === null ? null : strtolower(trim(explode(';', $header)[0]));
    }

    public function isHtml(): bool
    {
        return in_array($this->contentType(), ['text/html', 'application/xhtml+xml'], true);
    }

    public function contentMatches(string $pattern): bool
    {
        return preg_match($pattern, $this->content) === 1;
    }

    public function xpath(): ?DOMXPath
    {
        if (trim($this->content) === '') {
            return null;
        }

        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $loaded = $document->loadHTML('<?xml encoding="UTF-8">' . $this->content, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return $loaded ? new DOMXPath($document) : null;
    }

    # ====================================
    #   Cookies
    # ====================================

    public function cookies(): array
    {
        $cookies = [];

        foreach ($this->headerValues('set-cookie') as $header) {
            $cookie = SetCookie::fromHeader($header);

            if ($cookie instanceof SetCookie) {
                $cookies[] = $cookie;
            }
        }

        return $cookies;
    }

    public function cookie(string $name): ?SetCookie
    {
        foreach ($this->cookies() as $cookie) {
            if ($cookie->name === $name) {
                return $cookie;
            }
        }

        return null;
    }

    public function sessionCookies(): array
    {
        return array_values(array_filter(
            $this->cookies(),
            static fn(SetCookie $cookie): bool => $cookie->isSessionCookie() && !$cookie->isDeletion(),
        ));
    }
}
