<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use DOMElement;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'exposure.hydration-data',
    name: 'Hydration data',
    category: 'Exposure',
    description: 'Inspects state that server-side rendering frameworks embed into the page for the browser (Next.js __NEXT_DATA__, Nuxt __NUXT__, Redux and Apollo initial state, Remix context, Angular TransferState). Fails when it contains passwords, password hashes, secrets, tokens, database URLs or social security numbers, and warns about internal URLs and very large payloads, which usually mean whole database records are sent to the frontend. Found values are masked in the output.',
    remediation: <<<'TXT'
        Send to the page only the fields the UI really renders, map database records to dedicated DTOs / view models.
        Next.js: return only the needed props from getServerSideProps / getStaticProps, never whole ORM objects.
        Keep secrets and internal service URLs in server-only code and environment variables without a public prefix.
        Revoke and rotate every reported secret or token, it has to be considered leaked.
        TXT,
    references: [
        'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        'https://nextjs.org/docs/app/building-your-application/data-fetching/patterns#preventing-sensitive-data-from-being-exposed-to-the-client',
    ],
)]
final class HydrationDataRule implements RuleInterface
{
    private const int MAX_PAYLOAD_BYTES = 200 * 1024;

    private const int MAX_FINDINGS = 10;

    /** Ids of <script> elements holding the state as JSON */
    private const array SCRIPT_IDS = ['__NEXT_DATA__', '__NUXT_DATA__', 'ng-state'];

    /** Global variables the state is assigned to in an inline script */
    private const string GLOBAL_ASSIGNMENT = '~(?<![\w$])(?:window\.|self\.|globalThis\.)?(__NUXT__|__INITIAL_STATE__|__PRELOADED_STATE__|__APOLLO_STATE__|__INITIAL_DATA__|__remixContext)\s*=(?!=)~';

    /** Any "key": "string value" pair, in JSON as well as in a JavaScript object literal */
    private const string KEY_VALUE = '~["\']?([A-Za-z_$][\w$]*)["\']?\s*:\s*(?:"((?:[^"\\\\]|\\\\.)*)"|\'((?:[^\'\\\\]|\\\\.)*)\')~';

    /** Normalized key (lowercase, without _ and -) => kind of the value */
    private const array SENSITIVE_KEYS = [
        'password' => 'password',
        'passwd' => 'password',
        'passwordhash' => 'password',
        'hashedpassword' => 'password',
        'passhash' => 'password',
        'secret' => 'token',
        'clientsecret' => 'token',
        'apisecret' => 'token',
        'secretkey' => 'token',
        'privatekey' => 'token',
        'accesstoken' => 'token',
        'refreshtoken' => 'token',
        'databaseurl' => 'dsn',
        'dburl' => 'dsn',
        'ssn' => 'ssn',
    ];

    private const string INTERNAL_URL = '~\bhttps?://(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|[a-z0-9.-]+\.(?:internal|local|lan|corp))(?::\d+)?[^\s"\'<>]*~i';

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $payloads = $this->payloads($response);

        if ($payloads === []) {
            return RuleStatus::skip(
                rule: 'Hydration data',
                message: 'No server-rendered state found on the page',
            );
        }

        $leaks = [];
        $warnings = [];

        foreach ($payloads as $source => $payload) {
            foreach ($this->sensitiveValues($payload) as $key => $value) {
                $leaks[] = sprintf('%s: "%s" = %s', $source, $key, $this->mask($value));
            }

            if (preg_match_all(self::INTERNAL_URL, $payload, $matches) > 0) {
                $urls = array_slice(array_unique($matches[0]), 0, 3);
                $warnings[] = sprintf('%s contains internal URLs: %s', $source, implode(', ', $urls));
            }

            if (strlen($payload) > self::MAX_PAYLOAD_BYTES) {
                $warnings[] = sprintf('%s has %d kB, whole database records may be sent to the browser', $source, intdiv(strlen($payload), 1024));
            }
        }

        if ($leaks !== []) {
            $shown = array_slice($leaks, 0, self::MAX_FINDINGS);
            $more = count($leaks) - count($shown);

            return RuleStatus::fail(
                rule: 'Hydration data',
                message: 'Sensitive data in page state: ' . implode('; ', $shown) . ($more > 0 ? sprintf('; and %d more', $more) : ''),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'Hydration data',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'Hydration data',
            message: sprintf('No sensitive data found in %s', implode(', ', array_keys($payloads))),
        );
    }

    /**
     * @return array<string, string> source label => state as embedded in the page
     */
    private function payloads(HttpResponseInterface $response): array
    {
        $xpath = $response->xpath();

        if ($xpath === null) {
            return [];
        }

        $payloads = [];

        foreach ($xpath->query('//script[not(@src)]') ?: [] as $script) {
            if (!$script instanceof DOMElement) {
                continue;
            }

            $id = $script->getAttribute('id');
            $content = $script->textContent;

            // Angular names the TransferState script "ng-state", older versions "<appId>-state"
            $isStateScript = in_array($id, self::SCRIPT_IDS, true)
                || (str_ends_with($id, '-state') && strtolower($script->getAttribute('type')) === 'application/json');

            if ($isStateScript) {
                $payloads[$id] = ($payloads[$id] ?? '') . $content;
                continue;
            }

            if (preg_match(self::GLOBAL_ASSIGNMENT, $content, $match) === 1) {
                $payloads[$match[1]] = ($payloads[$match[1]] ?? '') . $content;
            }
        }

        return $payloads;
    }

    /**
     * @return array<string, string> key => value
     */
    private function sensitiveValues(string $payload): array
    {
        if (preg_match_all(self::KEY_VALUE, $payload, $matches, PREG_SET_ORDER) === 0) {
            return [];
        }

        $found = [];

        foreach ($matches as $match) {
            $key = $match[1];
            $kind = self::SENSITIVE_KEYS[strtolower(str_replace(['_', '-'], '', $key))] ?? null;
            $value = stripslashes(($match[2] ?? '') !== '' ? $match[2] : ($match[3] ?? ''));

            // the first sensitive value of every key is enough for the report
            if ($kind !== null && !isset($found[$key]) && $this->looksSensitive($kind, $value)) {
                $found[$key] = $value;
            }
        }

        return $found;
    }

    /**
     * Filters out labels and translations ("password": "Heslo"), placeholders and empty values.
     */
    private function looksSensitive(string $kind, string $value): bool
    {
        if ($value === '' || preg_match('~\s~', $value) === 1 || preg_match('~^[*•x.]+$~i', $value) === 1) {
            return false;
        }

        return match ($kind) {
            // password hash ($2y$, $argon2id$, …), hex digest, or a password-like string with a digit or a symbol
            'password' => preg_match('~^\$(?:2[abxy]?|argon2(?:id|i|d)?|\d)\$~', $value) === 1
                || preg_match('~^[a-f0-9]{32,}$~i', $value) === 1
                || (strlen($value) >= 8 && preg_match('~[\d\W_]~', $value) === 1 && preg_match('~[a-z]~i', $value) === 1),
            'token' => strlen($value) >= 16,
            'dsn' => preg_match('~^[a-z][a-z0-9+]*://~i', $value) === 1,
            'ssn' => preg_match('~^\d{3}-?\d{2}-?\d{4}$~', $value) === 1,
            default => false,
        };
    }

    /**
     * Keeps only the beginning of the value, e.g. "$2y$1…" or "eyJh…".
     */
    private function mask(string $value): string
    {
        return strlen($value) <= 12
            ? substr($value, 0, 2) . '…'
            : substr($value, 0, 6) . '…';
    }
}
