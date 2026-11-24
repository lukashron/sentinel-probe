<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Command;

use LukasHron\SentinelProbe\Rules\RuleStatus;
use LukasHron\SentinelProbe\ScanResult;
use LukasHron\SentinelProbe\SentinelProbe;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

#[AsCommand(name: 'sp:run', description: 'Run a security check against a target')]
class SentinelProbeCommand extends Command
{
    private const string FORMAT_TEXT = 'text';

    private const string FORMAT_JSON = 'json';

    public function __construct(
        private readonly SentinelProbe $sentinelProbe,
    )
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('url', InputArgument::OPTIONAL, 'URL of the target, asked interactively when omitted')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Output format: text or json', self::FORMAT_TEXT);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $format = $input->getOption('format');

        if (!in_array($format, [self::FORMAT_TEXT, self::FORMAT_JSON], true)) {
            $io->getErrorStyle()->error('Invalid format, expected text or json');
            return Command::FAILURE;
        }

        // in JSON mode stdout carries only the JSON, prompts and errors go to stderr
        $messages = $format === self::FORMAT_JSON ? $io->getErrorStyle() : $io;

        if ($format === self::FORMAT_TEXT) {
            $io->title('Security Tool');
        }

        $answer = $input->getArgument('url') ?? $messages->ask('Enter the URL of the target');
        $baseUrl = is_string($answer) ? trim($answer) : '';

        if (filter_var($baseUrl, FILTER_VALIDATE_URL) === false || preg_match('~^https?://~i', $baseUrl) !== 1) {
            $messages->error('Invalid URL, expected http(s)://...');
            return Command::FAILURE;
        }

        try {
            $results = $this->sentinelProbe->scan($baseUrl);
        } catch (TransportExceptionInterface $e) {
            $messages->error(sprintf('Target is unreachable: %s', $e->getMessage()));
            return Command::FAILURE;
        }

        $failed = array_filter($results, static fn(ScanResult $result): bool => $result->status->status === RuleStatus::FAIL) !== [];

        if ($format === self::FORMAT_JSON) {
            $this->writeJson($output, $baseUrl, $results);
        } else {
            $this->writeText($io, $results, $failed);
        }

        return $failed ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * @param list<ScanResult> $results
     */
    private function writeText(SymfonyStyle $io, array $results, bool $failed): void
    {
        foreach ($results as $result) {
            $badge = match ($result->status->status) {
                RuleStatus::OK => '<fg=green>[OK]  </>',
                RuleStatus::WARNING => '<fg=yellow>[WARN]</>',
                RuleStatus::FAIL => '<fg=red>[FAIL]</>',
                RuleStatus::SKIP => '<fg=gray>[SKIP]</>',
            };

            $io->writeln(sprintf(
                '%s <options=bold>%s</> %s',
                $badge,
                OutputFormatter::escape($result->status->rule),
                OutputFormatter::escape($result->status->message)
            ));
        }

        $io->newLine();

        $counts = array_count_values(array_map(static fn(ScanResult $result): string => $result->status->status, $results));

        $io->writeln(sprintf(
            '%d passed, %d warnings, %d failed, %d skipped',
            $counts[RuleStatus::OK] ?? 0,
            $counts[RuleStatus::WARNING] ?? 0,
            $counts[RuleStatus::FAIL] ?? 0,
            $counts[RuleStatus::SKIP] ?? 0,
        ));

        if ($failed) {
            $io->error('Security check found problems');
            return;
        }

        $io->success('Security check passed');
    }

    /**
     * @param list<ScanResult> $results
     */
    private function writeJson(OutputInterface $output, string $url, array $results): void
    {
        $output->writeln(json_encode(
            [
                'url' => $url,
                'results' => array_map(static fn(ScanResult $result): array => $result->toArray(), $results),
            ],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
        ), OutputInterface::OUTPUT_RAW);
    }
}
