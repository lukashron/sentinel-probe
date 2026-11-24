<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Domain;

use LukasHron\SentinelProbe\Dns\DnsResolver;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'domain.email-spoofing',
    name: 'Email spoofing',
    category: 'Domain',
    description: 'Checks the SPF and DMARC DNS records of the domain, which stop others from sending e-mails in its name (phishing of your users and partners). SPF must exist only once and end with ~all or -all, DMARC must have the policy quarantine or reject; p=none only monitors. Domains that send no e-mail should publish "v=spf1 -all" and p=reject as well.',
    remediation: <<<'TXT'
        example.com.        TXT "v=spf1 include:_spf.your-mail-provider.com -all"
        _dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        Domain without e-mail: "v=spf1 -all" and "v=DMARC1; p=reject"
        Start with p=none and rua reports, then move to quarantine and reject.
        TXT,
    references: [
        'https://www.rfc-editor.org/rfc/rfc7208',
        'https://www.rfc-editor.org/rfc/rfc7489',
        'https://cheatsheetseries.owasp.org/cheatsheets/Email_Spoofing_Cheat_Sheet.html',
    ],
)]
final readonly class EmailSpoofingRule implements RuleInterface
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
                rule: 'Email spoofing',
                message: 'Target is not addressed by a domain name',
            );
        }

        $domain = $this->mailDomain($host);
        $failures = [];
        $warnings = [];
        $summary = [];

        $spf = array_values(array_filter(
            $this->dns->txt($domain),
            static fn(string $record): bool => preg_match('~^v=spf1(\s|$)~i', $record) === 1,
        ));

        if ($spf === []) {
            $warnings[] = sprintf('%s has no SPF record', $domain);
        } elseif (count($spf) > 1) {
            $failures[] = sprintf('%s has %d SPF records, receivers treat it as an error (permerror)', $domain, count($spf));
        } elseif (preg_match('~\s([+?~-]?)all\b~i', $spf[0], $match) === 1) {
            $summary[] = sprintf('SPF %sall', $match[1]);

            if ($match[1] === '' || $match[1] === '+') {
                $failures[] = 'SPF +all allows any server to send e-mails for the domain';
            } elseif ($match[1] === '?') {
                $warnings[] = 'SPF ?all is neutral and does not stop spoofing, use ~all or -all';
            }
        } elseif (stripos($spf[0], 'redirect=') !== false) {
            $summary[] = 'SPF redirect';
        } else {
            $warnings[] = 'SPF has no all mechanism, other servers are not rejected, end it with -all';
        }

        $dmarc = $this->dmarc($domain);

        if ($dmarc === null) {
            $warnings[] = sprintf('_dmarc.%s has no DMARC record, spoofed e-mails are delivered', $domain);
        } else {
            $policy = preg_match('~(^|;)\s*p\s*=\s*(\w+)~i', $dmarc, $match) === 1 ? strtolower($match[2]) : null;
            $summary[] = sprintf('DMARC p=%s', $policy ?? 'missing');

            if (!in_array($policy, ['quarantine', 'reject'], true)) {
                $warnings[] = sprintf('DMARC p=%s only monitors, spoofed e-mails are delivered, use quarantine or reject', $policy ?? 'missing');
            }

            if (preg_match('~(^|;)\s*pct\s*=\s*(\d+)~i', $dmarc, $match) === 1 && (int)$match[2] < 100) {
                $warnings[] = sprintf('DMARC pct=%s applies the policy to part of the e-mails only', $match[2]);
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'Email spoofing',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Email spoofing',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'Email spoofing',
            message: sprintf('%s: %s', $domain, implode(', ', $summary)),
        );
    }

    /**
     * The closest domain with MX or SPF records, the host without www. otherwise.
     */
    private function mailDomain(string $host): string
    {
        foreach (DnsResolver::chain($host) as $name) {
            $hasSpf = array_filter($this->dns->txt($name), static fn(string $record): bool => stripos($record, 'v=spf1') === 0) !== [];

            if ($hasSpf || $this->dns->query($name, DNS_MX) !== []) {
                return $name;
            }
        }

        return (string)preg_replace('~^www\.~', '', $host);
    }

    /**
     * DMARC record of the domain or of its organizational (parent) domain.
     */
    private function dmarc(string $domain): ?string
    {
        foreach (DnsResolver::chain($domain) as $name) {
            foreach ($this->dns->txt('_dmarc.' . $name) as $record) {
                if (preg_match('~^v=DMARC1\s*(;|$)~i', $record) === 1) {
                    return $record;
                }
            }
        }

        return null;
    }
}
