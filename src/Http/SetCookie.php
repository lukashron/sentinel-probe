<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Http;

final readonly class SetCookie
{
    /**
     * @param array<string, string|true> $attributes lowercase attribute name => value (true for flags)
     */
    public function __construct(
        public string $name,
        public string $value,
        public array $attributes = [],
    )
    {
    }

    public static function fromHeader(string $header): ?self
    {
        $parts = explode(';', $header);
        $pair = array_shift($parts);

        if (!str_contains($pair, '=')) {
            return null;
        }

        [$name, $value] = explode('=', $pair, 2);
        $name = trim($name);

        if ($name === '') {
            return null;
        }

        $attributes = [];

        foreach ($parts as $part) {
            $part = trim($part);

            if ($part === '') {
                continue;
            }

            [$key, $attributeValue] = array_pad(explode('=', $part, 2), 2, null);
            $attributes[strtolower(trim((string)$key))] = $attributeValue === null ? true : trim($attributeValue);
        }

        return new self($name, trim($value), $attributes);
    }

    public function has(string $attribute): bool
    {
        return array_key_exists(strtolower($attribute), $this->attributes);
    }

    public function get(string $attribute): ?string
    {
        $value = $this->attributes[strtolower($attribute)] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * Cookies identifying the visitor's session or login:
     * PHPSESSID, JSESSIONID, ASP.NET_SessionId, laravel_session, SESS… (Drupal), sid, connect.sid, appSession (Auth0),
     * next-auth.session-token, __Host-auth, token, jwt, access_token, remember_web_… (Laravel), sb-…-auth-token (Supabase),
     * .AspNetCore.Identity.Application, .ASPXAUTH, wordpress_logged_in_…
     * CSRF tokens are excluded, JavaScript often has to read them.
     */
    public function isSessionCookie(): bool
    {
        if (preg_match('~csrf|xsrf~i', $this->name) === 1) {
            return false;
        }

        return preg_match('~sess|^(sid|connect\.sid)$|auth|token|jwt|^remember|logged_in|^\.aspnetcore\.(identity|cookies)~i', $this->name) === 1;
    }

    /**
     * Session of the native PHP session extension (session_start()), which session.use_strict_mode applies to:
     * PHPSESSID or a Drupal SESS…/SSESS… cookie.
     */
    public function isPhpSession(): bool
    {
        return preg_match('~^(PHPSESSID|S?SESS[0-9a-f]{32,})$~i', $this->name) === 1;
    }

    /**
     * Domain attribute widening the cookie to the domain and all its subdomains.
     */
    public function domain(): ?string
    {
        $domain = $this->get('domain');

        return $domain === null || $domain === '' ? null : strtolower(ltrim($domain, '.'));
    }

    /**
     * Cookie sent only to remove the session (e.g. session_destroy()).
     */
    public function isDeletion(): bool
    {
        $maxAge = $this->get('max-age');

        return $this->value === ''
            || strtolower($this->value) === 'deleted'
            || ($maxAge !== null && is_numeric($maxAge) && (int)$maxAge <= 0);
    }
}
