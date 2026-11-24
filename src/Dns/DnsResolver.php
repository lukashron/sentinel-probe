<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Dns;

/**
 * Thin wrapper around dns_get_record() using the system resolver.
 */
final class DnsResolver
{
    /**
     * @return list<array<string, mixed>> records, empty when the name does not exist or the lookup failed
     */
    public function query(string $name, int $type): array
    {
        // dns_get_record() emits a warning instead of returning an error for failed lookups
        set_error_handler(static fn(): bool => true);

        try {
            /** @var list<array<string, mixed>>|false $records */
            $records = dns_get_record($name, $type);
        } finally {
            restore_error_handler();
        }

        return is_array($records) ? $records : [];
    }

    /**
     * TXT records with their character strings joined.
     *
     * @return list<string>
     */
    public function txt(string $name): array
    {
        $texts = [];

        foreach ($this->query($name, DNS_TXT) as $record) {
            $entries = $record['entries'] ?? null;
            $text = is_array($entries) ? implode('', array_map(strval(...), array_filter($entries, is_scalar(...)))) : ($record['txt'] ?? null);

            if (is_string($text)) {
                $texts[] = $text;
            }
        }

        return $texts;
    }

    /**
     * Target of the CNAME record of the name, null when there is none.
     */
    public function cname(string $name): ?string
    {
        $target = $this->query($name, DNS_CNAME)[0]['target'] ?? null;

        return is_string($target) && $target !== '' ? strtolower(rtrim($target, '.')) : null;
    }

    public function resolves(string $name): bool
    {
        return $this->query($name, DNS_A) !== [] || $this->query($name, DNS_AAAA) !== [];
    }

    /**
     * The host and its parent domains with at least two labels, e.g. a.b.example.com, b.example.com, example.com.
     *
     * @return list<string>
     */
    public static function chain(string $host): array
    {
        $labels = explode('.', strtolower(rtrim($host, '.')));
        $chain = [];

        while (count($labels) >= 2) {
            $chain[] = implode('.', $labels);
            array_shift($labels);
        }

        return $chain;
    }

    public static function isIpAddress(string $host): bool
    {
        return filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false;
    }
}
