<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
final readonly class Rule
{
    /**
     * @param string $id stable identifier, e.g. "session.cookie-flags"
     * @param string $name short human-readable name shown in the scan output
     * @param string $category group the rule is listed under, e.g. "Session"
     * @param string $description what the rule checks and why it matters
     * @param string $remediation how to fix a failing check
     * @param list<string> $references links to further documentation
     * @param string|null $docs path to a detailed documentation file, relative to the project root
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $category,
        public string $description,
        public string $remediation = '',
        public array $references = [],
        public ?string $docs = null,
    )
    {
    }
}
