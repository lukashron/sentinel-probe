<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Rules\Exposure\DebugOutputRule;
use LukasHron\SentinelProbe\Rules\Exposure\SensitiveFilesRule;
use LukasHron\SentinelProbe\Rules\Headers\ClickjackingRule;
use LukasHron\SentinelProbe\Rules\Headers\ContentSecurityPolicyRule;
use LukasHron\SentinelProbe\Rules\Headers\ContentTypeOptionsRule;
use LukasHron\SentinelProbe\Rules\Headers\InformationDisclosureRule;
use LukasHron\SentinelProbe\Rules\Headers\PermissionsPolicyRule;
use LukasHron\SentinelProbe\Rules\Headers\ReferrerPolicyRule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use LukasHron\SentinelProbe\Rules\Session\SessionCookieRule;
use LukasHron\SentinelProbe\Rules\Session\SessionIdInUrlRule;
use LukasHron\SentinelProbe\Rules\Session\SessionStrictModeRule;
use LukasHron\SentinelProbe\Rules\Transport\HttpsRedirectRule;
use LukasHron\SentinelProbe\Rules\Transport\HttpsRule;
use LukasHron\SentinelProbe\Rules\Transport\StrictTransportSecurityRule;
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
     * @var RuleInterface[] $rules
     */
    private function rules(): array
    {
        return [
            new HttpsRule(),
            new HttpsRedirectRule($this->httpClient),
            new StrictTransportSecurityRule(),
            new ContentSecurityPolicyRule(),
            new ClickjackingRule(),
            new ContentTypeOptionsRule(),
            new ReferrerPolicyRule(),
            new PermissionsPolicyRule(),
            new InformationDisclosureRule(),
            new SessionCookieRule(),
            new SessionIdInUrlRule(),
            new SessionStrictModeRule($this->httpClient),
            new SensitiveFilesRule($this->httpClient),
            new DebugOutputRule($this->httpClient),
        ];
    }

    /**
     * @return list<RuleStatus>
     * @throws TransportExceptionInterface
     */
    public function scan(string $url): array
    {
        $response = new HttpResponse(
            $this->httpClient->request('GET', $url, ['timeout' => 10])
        );

        return array_map(
            static fn(RuleInterface $rule) => $rule->check($response),
            $this->rules()
        );
    }
}
