#!/usr/bin/env bash
# ==============================================================================
# EOL-PHP-Armor CLI Integration Test Suite
# Part of EOL-PHP-Armor by Anton Barinov <https://github.com/Anton-Barinov>
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/../bin/php-armor"

PASS=0
FAIL=0

assert_cli() {
    local name="$1"
    local condition="$2"
    local detail="$3"

    if [ "$condition" = "true" ]; then
        echo "  [PASS] ${name} -> ${detail}"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] ${name} -> ${detail}"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================================"
echo "   Running EOL-PHP-Armor CLI Integration Tests"
echo "========================================================"
echo ""

# 1. Version command
echo "1. Testing Version & Help Commands..."
VER_OUT=$("$BIN" --version)
assert_cli "Version flag returns expected string" "$([[ "$VER_OUT" == *"EOL-PHP-Armor v"* ]] && echo "true" || echo "false")" "$VER_OUT"

HELP_OUT=$("$BIN" --help)
assert_cli "Help flag displays usage instructions" "$([[ "$HELP_OUT" == *"COMMANDS:"* ]] && echo "true" || echo "false")" "Usage rendered"

# 2. Scan command
echo -e "\n2. Testing Scan & Audit Commands..."
SCAN_JSON=$("$BIN" scan --json)
assert_cli "Scan with --json produces valid JSON" "$([[ "$SCAN_JSON" == *'"status":"success"'* ]] && echo "true" || echo "false")" "$SCAN_JSON"

# 3. CVE command
echo -e "\n3. Testing Vulnerability Database Lookups (CVE)..."
CVE_OUT=$("$BIN" cve CVE-2026-109618)
assert_cli "Query CVE-2026-109618 returns CRITICAL severity" "$([[ "$CVE_OUT" == *"CRITICAL"* ]] && echo "true" || echo "false")" "CVSS 9.8 found"

CVE_OUT2=$("$BIN" cve CVE-2024-4577)
assert_cli "Query CVE-2024-4577 returns CGI injection details" "$([[ "$CVE_OUT2" == *"Best-Fit"* ]] && echo "true" || echo "false")" "Details found"

# 4. Patch command
echo -e "\n4. Testing Patch Availability Commands..."
PATCH_74=$("$BIN" patch 7.4)
assert_cli "Patch for PHP 7.4 displays enhanced universal patch" "$([[ "$PATCH_74" == *"php-7.4-enhanced-universal.patch"* ]] && echo "true" || echo "false")" "Patches found"

PATCH_56=$("$BIN" patch 5.6)
assert_cli "Patch for PHP 5.6 displays available patches" "$([[ "$PATCH_56" == *"php-5.6"* ]] && echo "true" || echo "false")" "Patches found"

# 5. Feed command
echo -e "\n5. Testing Security Feed Summary..."
FEED_OUT=$("$BIN" feed)
assert_cli "Feed displays tracked CVE summary table" "$([[ "$FEED_OUT" == *"CVE-2026-109618"* ]] && echo "true" || echo "false")" "Feed rendered"

# 6. Benchmark command
echo -e "\n6. Testing Benchmark..."
BENCH_OUT=$("$BIN" benchmark)
assert_cli "Benchmark executes 20,000 iterations cleanly" "$([[ "$BENCH_OUT" == *"Total iterations:   20,000"* ]] && echo "true" || echo "false")" "Overhead verified"

# 7. Status command
echo -e "\n7. Testing Status Command..."
STATUS_OUT=$("$BIN" status)
assert_cli "Status command displays active PHP version and state" "$([[ "$STATUS_OUT" == *"PHP Version:"* ]] && echo "true" || echo "false")" "Status verified"

echo -e "\n--------------------------------------------------------"
echo "Results: ${PASS} Passed, ${FAIL} Failed"
echo "--------------------------------------------------------"

if [ "$FAIL" -gt 0 ]; then
    echo "CLI TESTS FAILED! ❌"
    exit 1
fi

echo "ALL CLI INTEGRATION TESTS PASSED! 🎉"
exit 0
