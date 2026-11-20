#!/usr/bin/env php
<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe;

use LukasHron\SentinelProbe\Command\SentinelProbeCommand;
use Symfony\Component\Console\Application;
use Symfony\Component\HttpClient\HttpClient;

# ====================================
#   Check CLI
# ====================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This application must be run from the command line.\n");
    exit(1);
}

# ====================================
#   Composer
# ====================================

$autoload = __DIR__ . '/../vendor/autoload.php';

if (!is_file($autoload)) {
    fwrite(STDERR, "Dependencies are missing. Run \"composer install\" first.\n");
    exit(1);
}

require $autoload;

# ====================================
#   Application
# ====================================

final class App
{
    const string APP_NAME = 'Security Tool';
    const string APP_VERSION = '1.0.0';

    public function boot(): void
    {
        $httpClient = HttpClient::create([
            'headers' => ['User-Agent' => self::APP_NAME . '/' . self::APP_VERSION],
        ]);

        $command = new SentinelProbeCommand(
            new SentinelProbe($httpClient),
        );

        $application = new Application(self::APP_NAME, self::APP_VERSION);
        $application->addCommand($command);
        $application->setDefaultCommand(
            $command->getName() ?? throw new \LogicException('Command has no name.'),
            true,
        );

        exit($application->run());
    }
}

(new App())->boot();
