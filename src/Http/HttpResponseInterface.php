<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Http;

interface HttpResponseInterface
{
    # ====================================
    #   URL / HTTP
    # ====================================

    public function url(): string;

    public function statusCode(): int;

    public function scheme(): ?string;

    public function host(): ?string;

    public function isHttps(): bool;

    public function isSuccessful(): bool;

    public function isClientError(): bool;

    public function isServerError(): bool;

    # ====================================
    #   Headers
    # ====================================

    /**
     * @return array<string, list<string>> lowercase header name => values
     */
    public function headers(): array;

    public function hasHeader(string $name): bool;

    /**
     * First value of the header, trimmed.
     */
    public function header(string $name): ?string;

    /**
     * @return list<string>
     */
    public function headerValues(string $name): array;

    /**
     * All values of the header joined by a comma, as defined by RFC 9110.
     */
    public function headerLine(string $name): ?string;

    /**
     * Case-insensitive search in the header values.
     */
    public function headerContains(string $name, string $needle): bool;

    /**
     * Headers whose (lowercase) name matches the regular expression, e.g. '~^x-~'.
     *
     * @return array<string, list<string>>
     */
    public function findHeaders(string $pattern): array;

    # ====================================
    #   Content
    # ====================================

    public function content(): string;

    /**
     * MIME type without parameters, e.g. "text/html".
     */
    public function contentType(): ?string;

    public function isHtml(): bool;

    public function contentMatches(string $pattern): bool;

    # ====================================
    #   Cookies
    # ====================================

    /**
     * @return list<SetCookie>
     */
    public function cookies(): array;

    public function cookie(string $name): ?SetCookie;

    /**
     * Session cookies that are being set (not deleted).
     *
     * @return list<SetCookie>
     */
    public function sessionCookies(): array;
}
