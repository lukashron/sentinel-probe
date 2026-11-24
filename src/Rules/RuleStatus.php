<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules;

final readonly class RuleStatus
{
    public const string OK = 'ok';

    public const string WARNING = 'warning';

    public const string FAIL = 'fail';

    /** The rule does not apply to the target (nothing to verify), it counts neither as passed nor as failed. */
    public const string SKIP = 'skip';

    /**
     * @param self::OK|self::WARNING|self::FAIL|self::SKIP $status
     */
    public function __construct(
        public string $rule,
        public string $status,
        public string $message = '',
    )
    {
    }

    public static function ok(string $rule, string $message = ''): self
    {
        return new self($rule, self::OK, $message);
    }

    public static function warning(string $rule, string $message = ''): self
    {
        return new self($rule, self::WARNING, $message);
    }

    public static function fail(string $rule, string $message = ''): self
    {
        return new self($rule, self::FAIL, $message);
    }

    public static function skip(string $rule, string $message = ''): self
    {
        return new self($rule, self::SKIP, $message);
    }
}
