<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Headers;

use DOMElement;
use DOMXPath;
use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'headers.csp-nonce',
    name: 'CSP nonce',
    category: 'Headers',
    description: "Checks how the page uses CSP nonces: the nonce must change with every request, be long and unpredictable, and all <script>, <style> and <link> (stylesheet, preload, modulepreload) elements must carry it. Also reports inline event handlers, style attributes and javascript: links, which a nonce cannot allow.",
    remediation: <<<'TXT'
        Generate a new nonce for every response, e.g. base64_encode(random_bytes(16)),
        never cache it together with the page, and add nonce="…" to every <script>, <style> and <link>.
        Move inline event handlers (onclick="…") and style="…" attributes to scripts and stylesheets.
        TXT,
    references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/nonce',
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
    ],
)]
final readonly class CspNonceRule implements RuleInterface
{
    /** 128 bits encoded in base64 */
    private const int MIN_NONCE_LENGTH = 22;

    /** script types executed by the browser, other types (e.g. application/ld+json) are data blocks */
    private const array SCRIPT_TYPES = ['', 'text/javascript', 'application/javascript', 'module', 'importmap'];

    /** source expressions that do not allow any host */
    private const array KEYWORDS = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'strict-dynamic'", "'report-sample'", "'wasm-unsafe-eval'"];

    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        // the first enforced policy (header or <meta>) that uses nonces
        $policy = null;

        foreach ($response->contentSecurityPolicies() as $candidate) {
            if ($this->nonces($candidate) !== []) {
                $policy = $candidate;
                break;
            }
        }

        $nonces = $this->nonces($policy);

        if ($policy === null || $nonces === []) {
            return RuleStatus::skip(
                rule: 'CSP nonce',
                message: 'CSP does not use nonces, nothing to verify',
            );
        }

        $directives = ContentSecurityPolicyRule::parse($policy);
        $failures = [];
        $warnings = [];

        if ($this->isStatic($response, $nonces, $warnings)) {
            $failures[] = 'Nonce does not change between requests, attackers can reuse it';
        }

        if (count($nonces) > 1) {
            $warnings[] = sprintf('Policy contains %d different nonces, use one per response', count($nonces));
        }

        foreach ($nonces as $nonce) {
            if (strlen($nonce) < self::MIN_NONCE_LENGTH) {
                $warnings[] = sprintf('Nonce "%s" is too short, use at least 128 bits', $nonce);
            } elseif (ctype_digit($nonce)) {
                $warnings[] = sprintf('Nonce "%s" contains only digits and may be predictable', $nonce);
            }
        }

        $xpath = $response->xpath();

        if ($xpath instanceof \DOMXPath) {
            array_push($warnings, ...$this->checkElements($xpath, $directives, $nonces));
        }

        if ($failures !== []) {
            return RuleStatus::fail(
                rule: 'CSP nonce',
                message: implode('; ', [...$failures, ...$warnings]),
            );
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'CSP nonce',
                message: implode('; ', $warnings),
            );
        }

        return RuleStatus::ok(
            rule: 'CSP nonce',
            message: 'Nonce changes with every request and all elements carry it',
        );
    }

    /**
     * Requests the page again and compares the nonces.
     *
     * @param list<string> $nonces
     * @param list<string> $warnings
     */
    private function isStatic(HttpResponseInterface $response, array $nonces, array &$warnings): bool
    {
        try {
            $probe = new HttpResponse($this->httpClient->request('GET', $response->url(), ['timeout' => 10]));
        } catch (TransportExceptionInterface $e) {
            $warnings[] = sprintf('Could not verify that the nonce changes: %s', $e->getMessage());
            return false;
        }

        return array_intersect($nonces, $this->nonces(implode(';', $probe->contentSecurityPolicies()))) !== [];
    }

    /**
     * @param array<string, string> $directives
     * @param list<string> $nonces
     * @return list<string> warnings
     */
    private function checkElements(DOMXPath $xpath, array $directives, array $nonces): array
    {
        $scriptSources = $this->sources($directives, 'script-src-elem', 'script-src', 'default-src');
        $styleSources = $this->sources($directives, 'style-src-elem', 'style-src', 'default-src');

        /** @var array<string, int> $missing label => count */
        $missing = [];
        /** @var array<string, int> $mismatched label => count */
        $mismatched = [];

        foreach ($xpath->query('//script') ?: [] as $element) {
            if ($element instanceof DOMElement && in_array(strtolower(trim($element->getAttribute('type'))), self::SCRIPT_TYPES, true)) {
                $inline = !$element->hasAttribute('src');
                $label = $inline ? 'inline <script>' : '<script src>';
                $this->checkElement($element, $label, $inline, true, $scriptSources, $nonces, $missing, $mismatched);
            }
        }

        foreach ($xpath->query('//style') ?: [] as $element) {
            if ($element instanceof DOMElement) {
                $this->checkElement($element, 'inline <style>', true, false, $styleSources, $nonces, $missing, $mismatched);
            }
        }

        foreach ($xpath->query('//link') ?: [] as $element) {
            if (!$element instanceof DOMElement) {
                continue;
            }

            $rel = preg_split('~\s+~', strtolower(trim($element->getAttribute('rel')))) ?: [];
            $as = strtolower(trim($element->getAttribute('as')));

            if (in_array('stylesheet', $rel, true)) {
                $this->checkElement($element, '<link rel=stylesheet>', false, false, $styleSources, $nonces, $missing, $mismatched);
            } elseif (in_array('modulepreload', $rel, true)) {
                $this->checkElement($element, '<link rel=modulepreload>', false, true, $scriptSources, $nonces, $missing, $mismatched);
            } elseif (in_array('preload', $rel, true) && in_array($as, ['script', 'style'], true)) {
                $isScript = $as === 'script';
                $this->checkElement($element, sprintf('<link rel=preload as=%s>', $as), false, $isScript, $isScript ? $scriptSources : $styleSources, $nonces, $missing, $mismatched);
            }
        }

        $warnings = [];

        if ($missing !== []) {
            $warnings[] = 'Missing nonce, blocked by the browser: ' . $this->summary($missing);
        }

        if ($mismatched !== []) {
            $warnings[] = 'Nonce does not match the policy: ' . $this->summary($mismatched);
        }

        $handlers = $xpath->query('//@*[starts-with(name(), "on")]');

        if ($handlers !== false && $handlers->length > 0 && $this->blocksInline($this->sources($directives, 'script-src-attr', 'script-src', 'default-src'))) {
            $warnings[] = sprintf('%d inline event handlers (onclick, …) cannot be allowed by a nonce', $handlers->length);
        }

        $styles = $xpath->query('//@style');

        if ($styles !== false && $styles->length > 0 && $this->blocksInline($this->sources($directives, 'style-src-attr', 'style-src', 'default-src'))) {
            $warnings[] = sprintf('%d style attributes cannot be allowed by a nonce', $styles->length);
        }

        $links = $xpath->query('//*[@href][starts-with(translate(normalize-space(@href), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "javascript:")]');

        if ($links !== false && $links->length > 0 && $this->blocksInline($scriptSources)) {
            $warnings[] = sprintf('%d javascript: links cannot be allowed by a nonce', $links->length);
        }

        return $warnings;
    }

    /**
     * @param list<string> $nonces
     * @param array<string, int> $missing
     * @param array<string, int> $mismatched
     */
    private function checkElement(
        DOMElement $element,
        string $label,
        bool $inline,
        bool $isScript,
        ?string $sources,
        array $nonces,
        array &$missing,
        array &$mismatched,
    ): void
    {
        if ($sources === null || stripos($sources, "'nonce-") === false) {
            return;
        }

        $nonce = $element->getAttribute('nonce');

        if ($nonce !== '') {
            if (!in_array($nonce, $nonces, true)) {
                $mismatched[$label] = ($mismatched[$label] ?? 0) + 1;
            }

            return;
        }

        // inline elements may be allowed by a hash, external ones by a host source
        $allowed = $inline
            ? $this->allowedByHash($element->textContent, $sources)
            : !$this->externalNeedsNonce($sources, $isScript);

        if (!$allowed) {
            $missing[$label] = ($missing[$label] ?? 0) + 1;
        }
    }

    /**
     * @return list<string>
     */
    private function nonces(?string $policy): array
    {
        if ($policy === null || preg_match_all("~'nonce-([^']+)'~i", $policy, $matches) === 0) {
            return [];
        }

        return array_values(array_unique($matches[1]));
    }

    /**
     * @param array<string, string> $directives
     */
    private function sources(array $directives, string ...$names): ?string
    {
        foreach ($names as $name) {
            if (isset($directives[$name])) {
                return $directives[$name];
            }
        }

        return null;
    }

    private function allowedByHash(string $content, string $sources): bool
    {
        preg_match_all("~'(sha256|sha384|sha512)-([^']+)'~i", $sources, $matches, PREG_SET_ORDER);

        foreach ($matches as [, $algorithm, $hash]) {
            if (base64_encode(hash(strtolower($algorithm), $content, true)) === $hash) {
                return true;
            }
        }

        return false;
    }

    /**
     * External elements need a nonce when no host source can allow them.
     */
    private function externalNeedsNonce(string $sources, bool $isScript): bool
    {
        $lower = strtolower($sources);

        // 'strict-dynamic' makes browsers ignore host sources for scripts
        if ($isScript && str_contains($lower, "'strict-dynamic'")) {
            return true;
        }

        foreach (preg_split('~\s+~', trim($lower)) ?: [] as $source) {
            $isNonceOrHash = preg_match("~^'(nonce|sha256|sha384|sha512)-~", $source) === 1;

            if (!$isNonceOrHash && !in_array($source, self::KEYWORDS, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Inline code (handlers, style attributes, javascript: links) is blocked unless 'unsafe-inline'
     * applies; browsers ignore 'unsafe-inline' when a nonce or hash is present.
     */
    private function blocksInline(?string $sources): bool
    {
        if ($sources === null) {
            return false;
        }

        $lower = strtolower($sources);
        $hasNonceOrHash = preg_match("~'(nonce|sha256|sha384|sha512)-~", $lower) === 1;

        if (str_contains($lower, "'unsafe-hashes'")) {
            return false;
        }

        return $hasNonceOrHash || !str_contains($lower, "'unsafe-inline'");
    }

    /**
     * @param array<string, int> $counts
     */
    private function summary(array $counts): string
    {
        $parts = [];

        foreach ($counts as $label => $count) {
            $parts[] = sprintf('%s (%d×)', $label, $count);
        }

        return implode(', ', $parts);
    }
}
