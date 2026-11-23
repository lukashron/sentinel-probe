<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Http\PageAssets;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.js-secrets',
    name: 'Secrets in JavaScript',
    category: 'Exposure',
    description: 'Searches the page (inline scripts, hydration data such as __NEXT_DATA__) and same-origin scripts for secret keys that must never reach the browser: AWS access keys, Stripe secret keys, GitHub, Slack, SendGrid, OpenAI and Anthropic tokens, Supabase service_role keys and private keys. Public keys meant for the frontend (Stripe pk_live_, Firebase apiKey, Supabase anon key) are not reported. Found keys are masked in the output.',
    remediation: <<<'TXT'
        Revoke and rotate every reported key immediately, it has to be considered leaked.
        Call the services that need secret keys from your backend and send only the results to the browser.
        Bundlers include only variables with a public prefix (VITE_, NEXT_PUBLIC_, …), never give secrets such a name.
        TXT,
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    ],
)]
final readonly class JsSecretsRule implements RuleInterface
{
    private const int MAX_SCRIPTS = 10;

    /** Scripts are scanned whole up to this size. */
    private const int MAX_SCRIPT_BYTES = 5 * 1024 * 1024;

    /** label => pattern matching the whole secret */
    private const array PATTERNS = [
        'AWS access key' => '~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b~',
        'Stripe secret key' => '~\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b~',
        'GitHub token' => '~\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b~',
        'Slack token' => '~\bxox[baprs]-[0-9A-Za-z-]{10,}~',
        'SendGrid API key' => '~\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b~',
        'OpenAI API key' => '~\b(?:sk-(?:proj|svcacct|admin)-[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20})~',
        'Anthropic API key' => '~\bsk-ant-[a-z]+\d*-[0-9A-Za-z_-]{40,}~',
        'Private key' => '~-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----~',
    ];

    /** JWT candidates, reported only when the payload has the Supabase service_role */
    private const string JWT = '~\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}~';

    private PageAssets $pageAssets;

    public function __construct(
        HttpClientInterface $httpClient,
    )
    {
        $this->pageAssets = new PageAssets($httpClient);
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $xpath = $response->xpath();
        $scripts = $xpath instanceof DOMXPath ? $this->pageAssets->scripts($xpath, $response->url(), self::MAX_SCRIPTS) : [];

        $sources = ['the page' => $response->content()];

        foreach ($this->pageAssets->download($scripts, self::MAX_SCRIPT_BYTES) as $url => $content) {
            $sources[$url] = $content;
        }

        /** @var array<string, array{label: string, locations: list<string>}> $secrets secret => finding */
        $secrets = [];

        foreach ($sources as $location => $content) {
            foreach ($this->detect($content) as $secret => $label) {
                $secrets[$secret] ??= ['label' => $label, 'locations' => []];
                $secrets[$secret]['locations'][] = (string)$location;
            }
        }

        if ($secrets !== []) {
            $findings = [];

            foreach ($secrets as $secret => $finding) {
                $mask = $this->mask((string)$secret);
                $findings[] = sprintf('%s%s in %s', $finding['label'], $mask === null ? '' : ' ' . $mask, implode(', ', $finding['locations']));
            }

            return RuleStatus::fail(
                rule: 'Secrets in JavaScript',
                message: implode('; ', $findings),
            );
        }

        return RuleStatus::ok(
            rule: 'Secrets in JavaScript',
            message: sprintf('No secret keys found on the page and in %d scripts', count($sources) - 1),
        );
    }

    /**
     * @return array<string, string> secret => label
     */
    private function detect(string $content): array
    {
        $found = [];

        foreach (self::PATTERNS as $label => $pattern) {
            if (preg_match_all($pattern, $content, $matches) > 0) {
                foreach ($matches[0] as $secret) {
                    $found[$secret] = $label;
                }
            }
        }

        if (preg_match_all(self::JWT, $content, $matches) > 0) {
            foreach ($matches[0] as $token) {
                if ($this->isServiceRoleToken($token)) {
                    $found[$token] = 'Supabase service_role key';
                }
            }
        }

        return $found;
    }

    private function isServiceRoleToken(string $token): bool
    {
        $payload = explode('.', $token)[1] ?? '';
        $json = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);

        return is_array($json) && ($json['role'] ?? null) === 'service_role';
    }

    /**
     * Keeps only the beginning and the end of the secret, e.g. "sk_live_ab…xy".
     * Private keys are matched by their header only, there is nothing to show.
     */
    private function mask(string $secret): ?string
    {
        if (str_starts_with($secret, '-----BEGIN')) {
            return null;
        }

        return strlen($secret) <= 16
            ? substr($secret, 0, 4) . '…'
            : substr($secret, 0, 10) . '…' . substr($secret, -2);
    }
}
