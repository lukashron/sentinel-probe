<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules;

use Symfony\Contracts\HttpClient\ResponseInterface;

final class HttpsRule implements RuleInterface
{
    public function check(ResponseInterface $response): RuleStatus
    {
        $url = $response->getInfo('url');

        if (parse_url($url, PHP_URL_SCHEME) !== 'https') {
            return RuleStatus::fail('HTTPS', sprintf('Communication is not encrypted: %s', $url));
        }

        return RuleStatus::ok('HTTPS', sprintf('Communication runs over HTTPS: %s', $url));
    }
}
