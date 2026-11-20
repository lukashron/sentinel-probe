<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Transport;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;
use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleInterface;
use LukasHron\SentinelProbe\Rules\RuleStatus;

#[Rule(
    id: 'transport.tls-certificate',
    name: 'TLS certificate',
    category: 'Transport',
    description: 'Connects to the server and checks that the certificate is trusted and matches the domain, how many days remain until it expires, and whether the server still accepts the obsolete TLS 1.0 and 1.1 protocols.',
    remediation: <<<'TXT'
        Renew the certificate automatically (e.g. Let's Encrypt with certbot) and serve the full certificate chain.
        nginx: ssl_protocols TLSv1.2 TLSv1.3;
        Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3
        TXT,
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
    ],
)]
final class TlsCertificateRule implements RuleInterface
{
    private const int TIMEOUT = 10;

    private const int MIN_DAYS_LEFT = 14;

    public function check(HttpResponseInterface $response): RuleStatus
    {
        $host = $response->host();

        if (!$response->isHttps() || $host === null) {
            return RuleStatus::warning(
                rule: 'TLS certificate',
                message: 'Site is not served over HTTPS, there is no certificate to check',
            );
        }

        $port = parse_url($response->url(), PHP_URL_PORT);
        $port = is_int($port) ? $port : 443;

        $stream = $this->connect($host, $port, [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'capture_peer_cert' => true,
        ], $error);

        if ($stream === null) {
            return RuleStatus::fail(
                rule: 'TLS certificate',
                message: sprintf('Certificate is not trusted or does not match %s: %s', $host, $error),
            );
        }

        $certificate = stream_context_get_params($stream)['options']['ssl']['peer_certificate'] ?? null;
        $protocol = stream_get_meta_data($stream)['crypto']['protocol'] ?? 'unknown protocol';
        fclose($stream);

        $info = $certificate !== null ? openssl_x509_parse($certificate) : false;

        if ($info === false || !isset($info['validTo_time_t'])) {
            return RuleStatus::warning(
                rule: 'TLS certificate',
                message: 'Could not read the server certificate',
            );
        }

        $validTo = (int)$info['validTo_time_t'];
        $daysLeft = (int)floor(($validTo - time()) / 86400);
        $issuer = $info['issuer']['O'] ?? $info['issuer']['CN'] ?? 'unknown issuer';
        $summary = sprintf(
            'valid until %s (%d days), issued by %s, %s',
            date('Y-m-d', $validTo),
            $daysLeft,
            is_string($issuer) ? $issuer : implode(', ', (array)$issuer),
            $protocol,
        );

        if ($daysLeft < 0) {
            return RuleStatus::fail(
                rule: 'TLS certificate',
                message: sprintf('Certificate has expired: %s', $summary),
            );
        }

        $warnings = [];

        if ($daysLeft < self::MIN_DAYS_LEFT) {
            $warnings[] = sprintf('Certificate expires in less than %d days', self::MIN_DAYS_LEFT);
        }

        if ($this->acceptsLegacyTls($host, $port)) {
            $warnings[] = 'Server accepts obsolete TLS 1.0/1.1';
        }

        if ($warnings !== []) {
            return RuleStatus::warning(
                rule: 'TLS certificate',
                message: sprintf('%s; %s', implode('; ', $warnings), $summary),
            );
        }

        return RuleStatus::ok(
            rule: 'TLS certificate',
            message: sprintf('Certificate is %s', $summary),
        );
    }

    /**
     * Tries a handshake limited to TLS 1.0 and 1.1. OpenSSL disables them on the client side
     * by default, so the security level is lowered for this connection only.
     */
    private function acceptsLegacyTls(string $host, int $port): bool
    {
        $stream = $this->connect($host, $port, [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,
            'security_level' => 0,
            'ciphers' => 'DEFAULT@SECLEVEL=0',
        ], $error);

        if ($stream === null) {
            return false;
        }

        fclose($stream);

        return true;
    }

    /**
     * @param array<string, mixed> $ssl SSL context options
     * @return resource|null
     */
    private function connect(string $host, int $port, array $ssl, ?string &$error): mixed
    {
        $context = stream_context_create([
            'ssl' => $ssl + ['peer_name' => $host, 'SNI_enabled' => true],
        ]);

        error_clear_last();

        $stream = @stream_socket_client(
            sprintf('ssl://%s:%d', $host, $port),
            $errorCode,
            $errorMessage,
            self::TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($stream === false) {
            $error = $errorMessage !== '' ? $errorMessage : (error_get_last()['message'] ?? 'unknown error');
            return null;
        }

        return $stream;
    }
}
