<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Http;

final class Origin
{
    /**
     * scheme://host[:port] of the URL, null when the URL has no scheme or host.
     */
    public static function of(string $url): ?string
    {
        $parts = parse_url($url);

        if (!isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
