<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe;

use LukasHron\SentinelProbe\Rules\HttpsRule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final readonly class SentinelProbe
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    /**
     * @return list<RuleStatus>
     */
    public function scan(string $url): array
    {
        /** @var list<RuleInterface> $rules */
        $rules = [
            new HttpsRule()
        ];

        $response = $this->httpClient->request('GET', $url, ['timeout' => 10]);

        return array_map(
            static fn(RuleInterface $rule) => $rule->check($response), $rules
        );
    }
}
