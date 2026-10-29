<?php
/**
 * EOL-PHP-Armor: Autonomous Runtime Shield
 * 
 * High-performance, zero-dependency runtime WAF protecting EOL PHP (5.4–8.1)
 * from critical RCEs: php2shell (CVE-2026-109618/19), CGI Injection (CVE-2024-4577),
 * Filter Chains (CVE-2024-2961), Phar Deserialization, and Mail Parameter Injection.
 * 
 * Part of EOL-PHP-Armor by Anton Barinov <https://github.com/Anton-Barinov>
 * Tested on PHP 5.4 through 8.4 under OpenCart, WordPress, Laravel, Bitrix.
 */

if (defined('PHP_ARMOR_ACTIVE')) {
    return;
}
define('PHP_ARMOR_ACTIVE', true);
define('PHP_ARMOR_VERSION', '1.0.0');

final class PhpArmorShield
{
    private static $instance = null;
    private $startTime;
    private $config = [];
    private $logFile;

    public static function boot()
    {
        if (self::$instance === null) {
            self::$instance = new self();
            self::$instance->inspect();
        }
        return self::$instance;
    }

    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->loadConfiguration();
    }

    private function loadConfiguration()
    {
        $configFile = __DIR__ . '/armor-config.php';
        if (file_exists($configFile)) {
            $userConfig = include $configFile;
            if (is_array($userConfig)) {
                $this->config = $userConfig;
            }
        }

        // Built-in fail-safe defaults
        $defaults = [
            'mode'           => 'block', // 'block', 'monitor', or 'off'
            'log_enabled'    => true,
            'log_path'       => sys_get_temp_dir() . '/php-armor-incidents.log',
            'block_status'   => 403,
            'rules'          => [
                'php2shell'     => true,
                'cgi_injection' => true,
                'filter_chains' => true,
                'phar_wrappers' => true,
                'mail_abuse'    => true,
            ],
            'whitelist_ips'  => [],
        ];

        foreach ($defaults as $k => $v) {
            if (!isset($this->config[$k])) {
                $this->config[$k] = $v;
            }
        }

        $this->logFile = $this->config['log_path'];
    }

    public function inspect()
    {
        if (isset($this->config['mode']) && $this->config['mode'] === 'off') {
            return;
        }

        // Check IP Whitelist
        if ($this->isIpWhitelisted()) {
            return;
        }

        // 1. Host Header Injection & Splitting
        $hostViolation = $this->checkHostHeaders();
        if ($hostViolation !== null) {
            $this->block($hostViolation);
            return;
        }

        // 2. Vector: php2shell & Session Upload Progress (CVE-2026-109618 / 19)
        if (!empty($this->config['rules']['php2shell'])) {
            $v1 = $this->checkPhp2Shell();
            if ($v1 !== null) {
                $this->block($v1);
                return;
            }
        }

        // 3. Vector: CGI Argument Injection & Unicode Best-Fit (CVE-2024-4577 / CVE-2012-1823)
        if (!empty($this->config['rules']['cgi_injection'])) {
            $v2 = $this->checkCgiInjection();
            if ($v2 !== null) {
                $this->block($v2);
                return;
            }
        }

        // 4. Vector: PHP Filter Chains (CVE-2024-2961)
        if (!empty($this->config['rules']['filter_chains'])) {
            $v3 = $this->checkFilterChains();
            if ($v3 !== null) {
                $this->block($v3);
                return;
            }
        }

        // 5. Vector: Phar Deserialization (CVE-2018-17082)
        if (!empty($this->config['rules']['phar_wrappers'])) {
            $v4 = $this->checkPharWrappers();
            if ($v4 !== null) {
                $this->block($v4);
                return;
            }
        }

        // 6. Vector: Mail Parameter Injection & Null Bytes (CVE-2016-10033)
        if (!empty($this->config['rules']['mail_abuse'])) {
            $v5 = $this->checkMailAndNullBytes();
            if ($v5 !== null) {
                $this->block($v5);
                return;
            }
        }
    }

    private function isIpWhitelisted()
    {
        if (empty($this->config['whitelist_ips']) || !is_array($this->config['whitelist_ips'])) {
            return false;
        }
        $remoteIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        return in_array($remoteIp, $this->config['whitelist_ips'], true);
    }

    private function checkHostHeaders()
    {
        $headers = ['HTTP_HOST', 'HTTP_X_FORWARDED_HOST'];
        foreach ($headers as $h) {
            if (isset($_SERVER[$h]) && is_string($_SERVER[$h])) {
                $val = $_SERVER[$h];
                if (preg_match('/[\r\n\0]/', $val)) {
                    return [
                        'rule'    => 'HOST_HEADER_INJECTION',
                        'detail'  => 'CRLF or Null-byte injection detected in ' . $h,
                        'payload' => substr($val, 0, 64),
                    ];
                }
            }
        }
        return null;
    }

    public function checkPhp2Shell()
    {
        // Check upload progress key in POST
        $progressName = ini_get('session.upload_progress.name');
        if (!$progressName) {
            $progressName = 'PHP_SESSION_UPLOAD_PROGRESS';
        }

        if (isset($_POST[$progressName])) {
            $key = $_POST[$progressName];
            if (!is_string($key)) {
                return [
                    'rule'    => 'VEC1_PHP2SHELL_INVALID_TYPE',
                    'detail'  => 'Non-string payload in upload progress parameter',
                    'payload' => 'type=' . gettype($key),
                ];
            }
            if (strlen($key) > 256) {
                return [
                    'rule'    => 'VEC1_PHP2SHELL_EXCESSIVE_KEY_LENGTH',
                    'detail'  => 'Upload progress key length exceeds safe limit (256 bytes)',
                    'payload' => substr($key, 0, 64),
                ];
            }
            if (preg_match('/[\0\r\n|;]/', $key)) {
                return [
                    'rule'    => 'VEC1_PHP2SHELL_SERIALIZER_INJECTION',
                    'detail'  => 'Dangerous delimiter or control character in upload progress identifier',
                    'payload' => substr($key, 0, 64),
                ];
            }
        }

        // Check dangerous uploaded file extensions in $_FILES
        if (!empty($_FILES) && is_array($_FILES)) {
            $checkFiles = function($item, $depth = 0) use (&$checkFiles) {
                if ($depth > 16) return null;
                if (is_array($item)) {
                    foreach ($item as $k => $v) {
                        $res = $checkFiles($v, $depth + 1);
                        if ($res !== null) return $res;
                    }
                    return null;
                }
                if (is_string($item)) {
                    if (strpos($item, "\0") !== false) {
                        return [
                            'rule'    => 'VEC1_NULL_BYTE_FILENAME',
                            'detail'  => 'Null byte detected in uploaded file parameter',
                            'payload' => substr($item, 0, 64),
                        ];
                    }
                    // Direct executable script or double extension
                    if (preg_match('/\.(?:php[0-9]?|phtml|phar|pht|inc|cgi|pl|sh)\.[a-zA-Z0-9_\-]+$/i', $item) ||
                        preg_match('/\.(?:php[0-9]?|phtml|phar|pht|inc|cgi|pl|sh)$/i', $item)) {
                        return [
                            'rule'    => 'VEC1_DANGEROUS_UPLOAD_EXTENSION',
                            'detail'  => 'Direct executable script or double extension in upload filename',
                            'payload' => substr($item, 0, 64),
                        ];
                    }
                }
                return null;
            };

            foreach ($_FILES as $fileEntry) {
                if (isset($fileEntry['name'])) {
                    $res = $checkFiles($fileEntry['name']);
                    if ($res !== null) return $res;
                }
            }
        }

        return null;
    }

    public function checkCgiInjection()
    {
        $qs = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
        $target = $qs . ' ' . $uri;

        if ($target === ' ') {
            return null;
        }

        // Soft-hyphen / Windows Best-Fit mapping (%ad, \xad)
        if (preg_match('/(%ad|%u00ad|\xad)/i', $target)) {
            return [
                'rule'    => 'VEC2_CGI_BESTFIT_INJECTION',
                'detail'  => 'Unicode Best-Fit soft hyphen mapping exploit attempt (CVE-2024-4577)',
                'payload' => substr($target, 0, 128),
            ];
        }

        // Overlong UTF-8 path traversal
        if (preg_match('/(%c0%af|%c1%9c|%c0%2f|%c0%5c|%c0%ae|%c0%2e|%u2215|%u2216|%252e%252e|\.\.%5c|\.\.\\\\)/i', $target)) {
            return [
                'rule'    => 'VEC2_OVERLONG_UTF8_TRAVERSAL',
                'detail'  => 'Overlong UTF-8 or encoded backslash path traversal bypass attempt',
                'payload' => substr($target, 0, 128),
            ];
        }

        // Command-line arguments in Query String
        $patterns = [
            '/(?:^|&|\+|\s)-(?:d|s|w|f|n|c|b|-define|-syntax-check)\b/i',
            '/(?:^|&|\+|\s)%2d(?:d|s|w|f|n|c|b)/i',
            '/(?:allow_url_include|auto_prepend_file|auto_append_file)\s*=/i',
        ];
        $dec1 = urldecode($target);
        $dec2 = urldecode($dec1);

        foreach ($patterns as $p) {
            if (preg_match($p, $target) || preg_match($p, $dec1) || preg_match($p, $dec2)) {
                return [
                    'rule'    => 'VEC2_CGI_ARGUMENT_INJECTION',
                    'detail'  => 'CGI command-line switch injection attempt detected',
                    'payload' => substr($target, 0, 128),
                ];
            }
        }

        return null;
    }

    public function checkFilterChains()
    {
        $scan = function($val, $depth = 0) use (&$scan) {
            if ($depth > 16) return null;
            if (is_array($val)) {
                foreach ($val as $k => $v) {
                    $res = $scan($v, $depth + 1);
                    if ($res !== null) return $res;
                }
                return null;
            }
            if (is_string($val) && strlen($val) > 8) {
                $norm = rawurldecode(rawurldecode($val));
                if (stripos($norm, 'php://filter') !== false) {
                    if (substr_count($norm, 'convert.iconv.') >= 3 || substr_count($norm, 'resource=') > 0) {
                        return [
                            'rule'    => 'VEC3_FILTER_CHAIN_EXPLOIT',
                            'detail'  => 'PHP filter chain exploit pattern detected (CVE-2024-2961)',
                            'payload' => substr($val, 0, 128),
                        ];
                    }
                }
                if (stripos($norm, 'data://text/plain') !== false && stripos($norm, ';base64,') !== false) {
                    return [
                        'rule'    => 'VEC3_DATA_WRAPPER_EXECUTION',
                        'detail'  => 'data:// stream wrapper with base64 payload detected',
                        'payload' => substr($val, 0, 128),
                    ];
                }
            }
            return null;
        };

        if (!empty($_SERVER['REQUEST_URI']) && ($res = $scan($_SERVER['REQUEST_URI']))) return $res;
        if (!empty($_GET) && ($res = $scan($_GET))) return $res;
        if (!empty($_POST) && ($res = $scan($_POST))) return $res;
        return null;
    }

    public function checkPharWrappers()
    {
        $scan = function($val, $depth = 0) use (&$scan) {
            if ($depth > 16) return null;
            if (is_array($val)) {
                foreach ($val as $k => $v) {
                    $res = $scan($v, $depth + 1);
                    if ($res !== null) return $res;
                }
                return null;
            }
            if (is_string($val) && strlen($val) >= 7) {
                $norm = rawurldecode(rawurldecode($val));
                if (stripos($norm, 'phar://') !== false) {
                    return [
                        'rule'    => 'VEC4_PHAR_WRAPPER_INJECTION',
                        'detail'  => 'phar:// stream wrapper detected in user input (CVE-2018-17082)',
                        'payload' => substr($val, 0, 128),
                    ];
                }
                if (preg_match('/^O:\d+:"(?:Monolog\\\\Handler|GuzzleHttp\\\\Psr7|Symfony\\\\Component)/i', $norm)) {
                    return [
                        'rule'    => 'VEC4_POP_GADGET_INJECTION',
                        'detail'  => 'Serialized PHP POP exploit gadget chain detected in input',
                        'payload' => substr($val, 0, 128),
                    ];
                }
            }
            return null;
        };

        if (!empty($_SERVER['REQUEST_URI']) && ($res = $scan($_SERVER['REQUEST_URI']))) return $res;
        if (!empty($_GET) && ($res = $scan($_GET))) return $res;
        if (!empty($_POST) && ($res = $scan($_POST))) return $res;
        if (!empty($_COOKIE) && ($res = $scan($_COOKIE))) return $res;
        return null;
    }

    public function checkMailAndNullBytes()
    {
        // 1. Shellshock in headers
        $headers = ['HTTP_USER_AGENT', 'HTTP_REFERER'];
        foreach ($headers as $h) {
            if (isset($_SERVER[$h]) && is_string($_SERVER[$h])) {
                $v = $_SERVER[$h];
                if (strpos($v, '() {') !== false && strpos($v, '};') !== false) {
                    return [
                        'rule'    => 'VEC5_SHELLSHOCK_ATTEMPT',
                        'detail'  => 'Bash Shellshock injection signature in ' . $h,
                        'payload' => substr($v, 0, 128),
                    ];
                }
            }
        }

        // 2. Recursive null bytes & sendmail -X check
        $scan = function($key, $val, $depth = 0) use (&$scan) {
            if ($depth > 32) return null; // Prevent stack exhaustion
            if (is_array($val)) {
                foreach ($val as $k => $v) {
                    $res = $scan($k, $v, $depth + 1);
                    if ($res !== null) return $res;
                }
                return null;
            }
            if (is_string($val)) {
                $norm = rawurldecode(rawurldecode($val));
                if (strpos($val, "\0") !== false || strpos($norm, "\0") !== false || stripos($val, '%00') !== false) {
                    return [
                        'rule'    => 'VEC5_NULL_BYTE_POISONING',
                        'detail'  => 'Null-byte (%00) path truncation or poisoning attempt',
                        'payload' => substr($val, 0, 64),
                    ];
                }
                if (preg_match('/(?:^|\s)-(?:X|OQueueDirectory|C|o5)\b/i', $val)) {
                    return [
                        'rule'    => 'VEC5_MAIL_PARAMETER_INJECTION',
                        'detail'  => 'Dangerous sendmail switch (-X / -O / -C) detected (CVE-2016-10033)',
                        'payload' => substr($val, 0, 128),
                    ];
                }
            }
            return null;
        };

        if (!empty($_GET) && ($res = $scan('', $_GET))) return $res;
        if (!empty($_POST) && ($res = $scan('', $_POST))) return $res;
        if (!empty($_COOKIE) && ($res = $scan('', $_COOKIE))) return $res;
        return null;
    }

    private function block(array $violation)
    {
        $incidentId = 'arm_' . substr(md5(uniqid((string)mt_rand(), true)), 0, 10);
        $clientIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';

        $entry = [
            'timestamp'   => date('Y-m-d H:i:s'),
            'incident_id' => $incidentId,
            'client_ip'   => $clientIp,
            'rule'        => $violation['rule'],
            'detail'      => $violation['detail'],
            'payload'     => isset($violation['payload']) ? $violation['payload'] : '',
            'uri'         => $uri,
        ];

        // Atomic append to log with read-only filesystem fallback
        if (!empty($this->config['log_enabled']) && $this->logFile) {
            $line = json_encode($entry) . "\n";
            $written = @file_put_contents($this->logFile, $line, FILE_APPEND | LOCK_EX);
            if ($written === false) {
                // Read-only filesystem or unwritable log destination: fallback to system error_log
                @error_log("[EOL-PHP-Armor Incident {$incidentId}] " . $line);
            }
        }

        if (isset($this->config['mode']) && $this->config['mode'] === 'monitor') {
            return; // Audit only, do not terminate
        }

        // Send 403 response & exit
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=UTF-8');
            header('X-Protected-By: EOL-PHP-Armor');
        }

        echo "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style=\"font-family:sans-serif;text-align:center;padding:50px;\">";
        echo "<h2>403 Forbidden</h2>";
        echo "<p>Request blocked by <strong>EOL-PHP-Armor Shield</strong>.</p>";
        echo "<p><small>Incident ID: <code>{$incidentId}</code></small></p>";
        echo "</body></html>";
        exit(1);
    }
}

// Automatically boot runtime shield
PhpArmorShield::boot();
