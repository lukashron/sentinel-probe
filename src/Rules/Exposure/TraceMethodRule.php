<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Exposure;

use LukasHron\SentinelProbe\Http\HttpResponse;
use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[Rule(
    id: 'exposure.trace-method',
    name: 'TRACE method',
    category: 'Exposure',
    description: 'Sends a TRACE request with a marker header and checks whether the server echoes the request back. An enabled TRACE method reveals all request headers, including cookies and headers added by proxies (Cross-Site Tracing).',
    remediation: <<<'TXT'
        Apache: TraceEnable off
        nginx: TRACE is not supported by default, do not proxy it to the backend
        IIS: deny the TRACE verb in Request Filtering
        TXT,
    references: [
        'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
    ],
)]
final readonly class TraceMethodRule implements RuleInterface
{
    public function __construct(
        private HttpClientInterface $httpClient,
    )
    {
    }

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $marker = bin2hex(random_bytes(8));

        try {
            $probe = new HttpResponse($this->httpClient->request('TRACE', $response->url(), [
                'timeout' => 10,
                'max_redirects' => 0,
                'headers' => ['X-Sentinel-Probe' => $marker],
            ]));
        } catch (TransportExceptionInterface $e) {
            return RuleStatus::warning(
                rule: 'TRACE method',
                message: sprintf('Could not verify: %s', $e->getMessage()),
            );
        }

        $echoed = str_contains($probe->content(), $marker) || $probe->contentType() === 'message/http';

        if ($probe->isSuccessful() && $echoed) {
            return RuleStatus::fail(
                rule: 'TRACE method',
                message: 'Server echoes TRACE requests including all headers',
            );
        }

        return RuleStatus::ok(
            rule: 'TRACE method',
            message: sprintf('TRACE is not enabled (status %d)', $probe->statusCode()),
        );
    }
}
