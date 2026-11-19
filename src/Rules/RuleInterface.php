<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules;

use Symfony\Contracts\HttpClient\ResponseInterface;

interface RuleInterface
{
    public function check(ResponseInterface $response): RuleStatus;
}
