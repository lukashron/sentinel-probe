<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Command;

use LukasHron\SentinelProbe\Rules\RuleStatus;
use LukasHron\SentinelProbe\SentinelProbe;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

#[AsCommand(name: 'sp:run', description: 'Run a security check against a target')]
class SentinelProbeCommand extends Command
{
    public function __construct(
        private readonly SentinelProbe $sentinelProbe,
    )
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Security Tool');

        $baseUrl = trim((string)$io->ask('Enter the URL of the target'));

        if (filter_var($baseUrl, FILTER_VALIDATE_URL) === false || preg_match('~^https?://~i', $baseUrl) !== 1) {
            $io->error('Invalid URL, expected http(s)://...');
            return Command::FAILURE;
        }

        try {
            $results = $this->sentinelProbe->scan($baseUrl);
        } catch (TransportExceptionInterface $e) {
            $io->error(sprintf('Target is unreachable: %s', $e->getMessage()));
            return Command::FAILURE;
        }

        $failed = false;

        foreach ($results as $status) {

            $badge = match ($status->status) {
                RuleStatus::OK => '<fg=green>[OK]  </>',
                RuleStatus::WARNING => '<fg=yellow>[WARN]</>',
                RuleStatus::FAIL => '<fg=red>[FAIL]</>'
            };

            $io->writeln(sprintf(
                '%s <options=bold>%s</> %s',
                $badge,
                OutputFormatter::escape($status->rule),
                OutputFormatter::escape($status->message)
            ));

            $failed = $failed || $status->status === RuleStatus::FAIL;
        }

        $io->newLine();

        if ($failed) {
            $io->error('Security check found problems');
            return Command::FAILURE;
        }

        $io->success('Security check passed');
        return Command::SUCCESS;
    }
}
