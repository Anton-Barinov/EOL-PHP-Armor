<?php
/**
 * Master Test Suite Runner for EOL-PHP-Armor
 * Part of EOL-PHP-Armor by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

echo "==========================================================\n";
echo "       EOL-PHP-Armor Complete Verification Suite\n";
echo "==========================================================\n\n";

$failed = false;
$startTime = microtime(true);

echo ">>> [1/3] Running Unit & Exploit Prevention Tests...\n";
passthru(PHP_BINARY . ' ' . escapeshellarg(__DIR__ . '/test_runtime_armor.php'), $code1);
if ($code1 !== 0) $failed = true;

echo "\n>>> [2/3] Running CLI Integration & Command Tests...\n";
passthru('bash ' . escapeshellarg(__DIR__ . '/test_cli.sh'), $code2);
if ($code2 !== 0) $failed = true;

echo "\n>>> [3/3] Running Chaos & Fault-Injection Tests...\n";
passthru(PHP_BINARY . ' ' . escapeshellarg(__DIR__ . '/test_chaos.php'), $code3);
if ($code3 !== 0) $failed = true;

$binArmor = dirname(__DIR__) . '/bin/php-armor';
passthru(escapeshellarg($binArmor) . ' verify-patches', $code4);
if ($code4 !== 0) $failed = true;

$elapsed = round((microtime(true) - $startTime) * 1000, 2);

echo "\n----------------------------------------------------------\n";
if ($failed) {
    echo "❌ EOL-PHP-Armor Verification Suite Failed! ({$elapsed} ms)\n";
    exit(1);
} else {
    echo "🎉 ALL EOL-PHP-ARMOR TEST SUITES PASSED CLEANLY! ({$elapsed} ms)\n";
    exit(0);
}
