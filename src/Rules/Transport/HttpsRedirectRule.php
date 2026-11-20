<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Transport;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TimeoutExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'transport.https-redirect',
    name: 'HTTPS redirect',
    category: 'Transport',
    description: 'Requests the plain HTTP version of the site and checks that it permanently redirects (301 or 308) to HTTPS. Without the redirect, users typing the address without https:// stay on an unencrypted connection.',
    remediation: "nginx: server { listen 80; return 301 https://\$host\$request_uri; }\nApache: Redirect permanent / https://example.com/",
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
    ],
)]
final readonly class HttpsRedirectRule implements RuleInterface
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $host = $response->host();

        if ($host === null) {
            return RuleStatus::warning(
                rule: 'HTTPS redirect',
                message: sprintf('Could not determine the target host from %s', $response->url()),
            );
        }

        $httpUrl = 'http://' . $host . '/';

        try {
            $probe = new HttpResponse($this->httpClient->request('GET', $httpUrl, [
                'timeout' => 10,
                'max_redirects' => 0,
            ]));
        } catch (TimeoutExceptionInterface) {
            return RuleStatus::warning(
                rule: 'HTTPS redirect',
                message: sprintf('%s timed out, could not verify the redirect', $httpUrl),
            );
        } catch (TransportExceptionInterface) {
            // port 80 is closed: nothing is served over plain HTTP
            return RuleStatus::ok(
                rule: 'HTTPS redirect',
                message: sprintf('%s is not reachable, the site is not served over plain HTTP', $httpUrl),
            );
        }

        $status = $probe->statusCode();
        $location = $probe->header('location');

        if ($location === null || $status < 300 || $status >= 400) {
            return RuleStatus::fail(
                rule: 'HTTPS redirect',
                message: sprintf('%s does not redirect to HTTPS (status %d)', $httpUrl, $status),
            );
        }

        if (!str_starts_with(strtolower($location), 'https://')) {
            return RuleStatus::fail(
                rule: 'HTTPS redirect',
                message: sprintf('%s redirects to %s, which is not HTTPS', $httpUrl, $location),
            );
        }

        if (!in_array($status, [301, 308], true)) {
            return RuleStatus::warning(
                rule: 'HTTPS redirect',
                message: sprintf('%s redirects to %s with temporary status %d, use 301 or 308', $httpUrl, $location, $status),
            );
        }

        return RuleStatus::ok(
            rule: 'HTTPS redirect',
            message: sprintf('%s permanently redirects to %s (%d)', $httpUrl, $location, $status),
        );
    }
}
