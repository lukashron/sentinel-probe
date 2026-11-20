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
     * PHPSESSID, JSESSIONID, ASP.NET_SessionId, laravel_session, SESS… (Drupal), sid, connect.sid
     */
    public function isSessionCookie(): bool
    {
        return preg_match('~sess|^(sid|connect\.sid)$~i', $this->name) === 1;
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
