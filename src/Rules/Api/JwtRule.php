<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Api;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'api.jwt',
    name: 'JWT',
    category: 'API',
    description: 'Finds JSON Web Tokens in cookies, response headers and the page and inspects them offline: alg "none" (unsigned token anybody can forge), HMAC tokens (HS256/384/512) signed with a common weak secret that can be guessed, tokens without expiration or valid for more than 30 days, and sensitive data in the payload, which is only base64-encoded and readable by anyone. Public Supabase anon keys are not checked for expiration.',
    remediation: <<<'TXT'
        Always verify the signature with a fixed algorithm list on the server and reject alg "none".
        Use a random HMAC secret of at least 256 bits (e.g. base64_encode(random_bytes(32))), or asymmetric keys (RS256, ES256, EdDSA).
        Keep access tokens short-lived (minutes) and use rotated refresh tokens; never put passwords or personal data into the payload.
        TXT,
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
        'https://portswigger.net/web-security/jwt',
        'https://datatracker.ietf.org/doc/html/rfc8725',
    ],
)]
final class JwtRule implements RuleInterface
{
    private const string JWT = '~\beyJ[0-9A-Za-z_-]{5,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]*~';

    private const int MAX_LIFETIME = 30 * 24 * 3600;

    /** Secrets found in tutorials, defaults of libraries and leaked configurations */
    private const array WEAK_SECRETS = [
        'secret', 'secretkey', 'secret_key', 'secret-key', 'mysecret', 'my_secret', 'supersecret', 'topsecret', 's3cr3t',
        'password', 'passw0rd', '123456', '12345678', '1234567890', 'qwerty', 'changeme', 'change_me', 'default', 'test',
        'admin', 'key', 'private', 'token', 'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret', 'your-256-bit-secret',
        'your-secret-key', 'your_secret_key', 'your_jwt_secret', 'shhhhh', 'keyboard cat', 'HS256', '',
    ];

    private const array HMAC_ALGORITHMS = ['HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512'];

    private const string SENSITIVE_KEYS = '~^(password|passwd|pwd|pass|secret|client_secret|api_?key|private_?key|ssn|card_?number|cc_?number|cvv|iban)$~i';

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $tokens = $this->tokens($response);

        if ($tokens === []) {
            return RuleStatus::skip(
                rule: 'JWT',
                message: 'No JSON Web Token found in cookies, headers or the page',
            );
        }

        $failures = [];
        $warnings = [];
        $algorithms = [];

        foreach ($tokens as $token => $location) {
            [$encodedHeader, $encodedPayload, $signature] = array_pad(explode('.', $token, 3), 3, '');
            $header = $this->decode($encodedHeader);
            $payload = $this->decode($encodedPayload);

            if ($header === null || $payload === null || !is_string($header['alg'] ?? null)) {
                continue;
            }

            $algorithm = $header['alg'];
            $algorithms[] = $algorithm;
            $label = sprintf('token in %s', $location);

            if (strtolower($algorithm) === 'none') {
                $failures[] = sprintf('%s uses alg "none", it is not signed and anybody can forge it', $label);
                continue;
            }

            $weakSecret = $this->weakSecret($algorithm, $encodedHeader . '.' . $encodedPayload, $signature);

            if ($weakSecret !== null) {
                $failures[] = sprintf('%s is signed with the weak secret "%s", anybody can forge it', $label, $weakSecret);
            }

            if (($payload['role'] ?? null) !== 'anon') {
                $lifetime = $this->lifetime($payload);

                if ($lifetime === null) {
                    $warnings[] = sprintf('%s has no expiration (exp), a stolen token is valid forever', $label);
                } elseif ($lifetime > self::MAX_LIFETIME) {
                    $warnings[] = sprintf('%s is valid for %d days', $label, intdiv($lifetime, 86400));
                }
            }

            $sensitive = array_values(array_filter(
                array_map(strval(...), array_keys($payload)),
                static fn(string $key): bool => preg_match(self::SENSITIVE_KEYS, $key) === 1,
            ));

            if ($sensitive !== []) {
                $warnings[] = sprintf('%s contains %s in the payload, which anyone can read', $label, implode(', ', $sensitive));
            }
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'JWT',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'JWT',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'JWT',
            message: sprintf('%d tokens (%s): signed, short-lived and without sensitive data', count($tokens), implode(', ', array_unique($algorithms))),
        );
    }

    /**
     * @return array<string, string> token => where it was found
     */
    private function tokens(HttpResponseInterface $response): array
    {
        $tokens = [];

        foreach ($response->cookies() as $cookie) {
            if (preg_match_all(self::JWT, rawurldecode($cookie->value), $matches) > 0) {
                foreach ($matches[0] as $token) {
                    $tokens[$token] ??= sprintf('cookie %s', $cookie->name);
                }
            }
        }

        foreach ($response->headers() as $name => $values) {
            if ($name === 'set-cookie') {
                continue;
            }

            foreach ($values as $value) {
                if (preg_match_all(self::JWT, $value, $matches) > 0) {
                    foreach ($matches[0] as $token) {
                        $tokens[$token] ??= sprintf('header %s', $name);
                    }
                }
            }
        }

        if (preg_match_all(self::JWT, $response->content(), $matches) > 0) {
            foreach ($matches[0] as $token) {
                $tokens[$token] ??= 'the page';
            }
        }

        return $tokens;
    }

    /**
     * @return array<mixed>|null
     */
    private function decode(string $part): ?array
    {
        $json = json_decode(base64_decode(strtr($part, '-_', '+/')), true);

        return is_array($json) ? $json : null;
    }

    private function weakSecret(string $algorithm, string $signingInput, string $signature): ?string
    {
        $hash = self::HMAC_ALGORITHMS[strtoupper($algorithm)] ?? null;

        if ($hash === null || $signature === '') {
            return null;
        }

        foreach (self::WEAK_SECRETS as $secret) {
            $expected = rtrim(strtr(base64_encode(hash_hmac($hash, $signingInput, $secret, true)), '+/', '-_'), '=');

            if (hash_equals($expected, $signature)) {
                return $secret;
            }
        }

        return null;
    }

    /**
     * Seconds between issuing (or now) and expiration, null when the token does not expire.
     *
     * @param array<mixed> $payload
     */
    private function lifetime(array $payload): ?int
    {
        $exp = $payload['exp'] ?? null;

        if (!is_int($exp) && !is_float($exp)) {
            return null;
        }

        $iat = $payload['iat'] ?? null;
        $start = is_int($iat) || is_float($iat) ? (int)$iat : time();

        return max(0, (int)$exp - $start);
    }
}
