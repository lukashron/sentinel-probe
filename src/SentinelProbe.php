<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Rules\Content\SubresourceIntegrityRule;
use LukasHron\SentinelProbe\Rules\Exposure\DebugOutputRule;
use LukasHron\SentinelProbe\Rules\Exposure\DirectoryListingRule;
use LukasHron\SentinelProbe\Rules\Exposure\SensitiveFilesRule;
use LukasHron\SentinelProbe\Rules\Exposure\TraceMethodRule;
use LukasHron\SentinelProbe\Rules\Headers\ClickjackingRule;
use LukasHron\SentinelProbe\Rules\Headers\ContentSecurityPolicyRule;
use LukasHron\SentinelProbe\Rules\Headers\ContentTypeOptionsRule;
use LukasHron\SentinelProbe\Rules\Headers\CorsRule;
use LukasHron\SentinelProbe\Rules\Headers\CspNonceRule;
use LukasHron\SentinelProbe\Rules\Headers\InformationDisclosureRule;
use LukasHron\SentinelProbe\Rules\Headers\PermissionsPolicyRule;
use LukasHron\SentinelProbe\Rules\Headers\ReferrerPolicyRule;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\Session\CookieFlagsRule;
use LukasHron\SentinelProbe\Rules\Session\SessionCacheRule;
use LukasHron\SentinelProbe\Rules\Session\SessionCookieRule;
use LukasHron\SentinelProbe\Rules\Session\SessionIdInUrlRule;
use LukasHron\SentinelProbe\Rules\Session\SessionStrictModeRule;
use LukasHron\SentinelProbe\Rules\Transport\HttpsRedirectRule;
use LukasHron\SentinelProbe\Rules\Transport\HttpsRule;
use LukasHron\SentinelProbe\Rules\Transport\MixedContentRule;
use LukasHron\SentinelProbe\Rules\Transport\StrictTransportSecurityRule;
use LukasHron\SentinelProbe\Rules\Transport\TlsCertificateRule;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final readonly class SentinelProbe
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    /**
     * @return list<RuleInterface>
     */
    private function rules(): array
    {
        return [
            new HttpsRule(),
            new HttpsRedirectRule($this->httpClient),
            new TlsCertificateRule(),
            new MixedContentRule(),
            new SubresourceIntegrityRule(),
            new StrictTransportSecurityRule(),
            new ContentSecurityPolicyRule(),
            new CspNonceRule($this->httpClient),
            new ClickjackingRule(),
            new CorsRule($this->httpClient),
            new ContentTypeOptionsRule(),
            new ReferrerPolicyRule(),
            new PermissionsPolicyRule(),
            new InformationDisclosureRule(),
            new SessionCookieRule(),
            new CookieFlagsRule(),
            new SessionIdInUrlRule(),
            new SessionStrictModeRule($this->httpClient),
            new SessionCacheRule(),
            new SensitiveFilesRule($this->httpClient),
            new DebugOutputRule($this->httpClient),
            new DirectoryListingRule($this->httpClient),
            new TraceMethodRule($this->httpClient),
        ];
    }

    /**
     * @return list<ScanResult>
     * @throws TransportExceptionInterface
     */
    public function scan(string $url): array
    {
        $response = new HttpResponse(
            $this->httpClient->request('GET', $url, ['timeout' => 10])
        );

        return array_map(
            static fn(RuleInterface $rule): ScanResult => new ScanResult(self::metadata($rule), $rule->check($response)),
            $this->rules()
        );
    }

    private static function metadata(RuleInterface $rule): Rule
    {
        $attribute = (new \ReflectionClass($rule))->getAttributes(Rule::class)[0] ?? null;

        return $attribute?->newInstance() ?? throw new \LogicException(sprintf('Rule %s has no #[Rule] attribute', $rule::class));
    }
}
