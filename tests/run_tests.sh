#!/usr/bin/env bash
# ==============================================================================
# EOL-PHP-Armor: Master Test Suite Runner
# Part of EOL-PHP-Armor by Anton Barinov <https://github.com/Anton-Barinov>
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo "       EOL-PHP-Armor Complete Verification Suite"
echo "=========================================================="
echo ""

FAILED=0

echo ">>> [1/3] Running Unit & Exploit Prevention Tests..."
php "${SCRIPT_DIR}/test_runtime_armor.php" || FAILED=1

echo ""
echo ">>> [2/3] Running CLI Integration & Command Tests..."
bash "${SCRIPT_DIR}/test_cli.sh" || FAILED=1

echo ""
echo ">>> [3/3] Running Chaos & Fault-Injection Tests..."
php "${SCRIPT_DIR}/test_chaos.php" || FAILED=1
"${SCRIPT_DIR}/../bin/php-armor" verify-patches >/dev/null || FAILED=1

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "❌ Verification Suite Failed!"
    exit 1
fi

echo "🎉 ALL EOL-PHP-ARMOR TEST SUITES PASSED CLEANLY!"
exit 0
