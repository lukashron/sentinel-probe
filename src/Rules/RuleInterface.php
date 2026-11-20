<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules;

use LukasHron\SentinelProbe\Http\HttpResponseInterface;

interface RuleInterface
{
    public function check(HttpResponseInterface $response): RuleStatus;
}
