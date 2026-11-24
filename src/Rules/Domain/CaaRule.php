<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Domain;

use LukasHron\SentinelProbe\Dns\DnsResolver;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'domain.caa',
    name: 'CAA',
    category: 'Domain',
    description: 'Checks the DNS CAA records of the target host and its parent domains (the closest one applies). CAA lists the certificate authorities allowed to issue certificates for the domain, without it any authority may do so, which makes a mis-issued or fraudulently obtained certificate easier.',
    remediation: <<<'TXT'
        Add CAA records for the authorities you use, e.g.
        example.com. CAA 0 issue "letsencrypt.org"
        example.com. CAA 0 issuewild ";"
        example.com. CAA 0 iodef "mailto:security@example.com"
        TXT,
    references: [
        'https://www.rfc-editor.org/rfc/rfc8659',
        'https://letsencrypt.org/docs/caa/',
    ],
)]
final readonly class CaaRule implements RuleInterface
{
    public function __construct(
        private DnsResolver $dns,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $host = $response->host();

        if ($host === null || DnsResolver::isIpAddress($host)) {
            return RuleStatus::skip(
                rule: 'CAA',
                message: 'Target is not addressed by a domain name',
            );
        }

        foreach (DnsResolver::chain($host) as $name) {
            $records = $this->dns->query($name, DNS_CAA);

            if ($records === []) {
                continue;
            }

            $entries = [];
            $hasIodef = false;

            foreach ($records as $record) {
                $tag = is_string($record['tag'] ?? null) ? strtolower($record['tag']) : '';
                $value = is_scalar($record['value'] ?? null) ? (string)$record['value'] : '';
                $hasIodef = $hasIodef || $tag === 'iodef';

                if (in_array($tag, ['issue', 'issuewild'], true)) {
                    $entries[] = sprintf('%s "%s"', $tag, $value);
                }
            }

            return RuleStatus::ok(
                rule: 'CAA',
                message: sprintf('%s: %s', $name, implode(', ', $entries)) . ($hasIodef ? '' : ' (consider iodef for violation reports)'),
            );
        }

        return RuleStatus::warning(
            rule: 'CAA',
            message: sprintf('No CAA record for %s or its parent domains, any certificate authority may issue certificates', $host),
        );
    }
}
