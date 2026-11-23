<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe;

use LukasHron\SentinelProbe\Rules\Attribute\Rule;
use LukasHron\SentinelProbe\Rules\RuleStatus;

final readonly class ScanResult
{
    public function __construct(
        public Rule $rule,
        public RuleStatus $status,
    )
    {
    }

    /**
     * @return array{id: string, category: string, name: string, status: string, message: string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->rule->id,
            'category' => $this->rule->category,
            'name' => $this->rule->name,
            'status' => $this->status->status,
            'message' => $this->status->message,
        ];
    }
}
