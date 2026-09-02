#!/usr/bin/env bash
# Regression tests for two real, previously-shipped bugs found by manual
# testing (see CHANGELOG 3.1.1):
#
#   1. install.sh silently aborted with an unexplained `exit 1` whenever
#      re-run non-interactively (closed/empty stdin) with an API key
#      already configured -- `read` fails at EOF and `set -e` killed the
#      script before it could explain why.
#   2. update.sh --check-only --json's "notified" field reported whether
#      the proxy binary was merely *executable*, not whether a
#      notification was actually attempted.
#
# Neither is something the Python test suite can exercise (they're pure
# shell-script behavior), so this exists specifically to keep both fixed
# going forward. Run from the repo root: bash tests/test_shell_scripts.sh
#
# Destructive: writes to /etc/abuseipdb-proxy, /usr/local/bin,
# /var/lib/abuseipdb-proxy, /etc/systemd/system. Intended for an ephemeral
# CI runner or a throwaway container/VM -- do not run this on a real
# proxy host.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

PASS=0
FAIL=0

ok() {
    echo "  OK: $1"
    PASS=$((PASS + 1))
}

bad() {
    echo "  FAIL: $1" >&2
    FAIL=$((FAIL + 1))
}

reset_install_state() {
    rm -f /usr/local/bin/abuseipdb_proxy.py
    rm -rf /etc/abuseipdb-proxy
    rm -rf /var/lib/abuseipdb-proxy
    rm -f /etc/systemd/system/abuseipdb-proxy.service
}

echo "=== Setting up a throwaway git checkout for update.sh tests ==="
BARE="${WORKDIR}/remote.git"
git init -q --bare "${BARE}"
git -C "${BARE}" symbolic-ref HEAD refs/heads/main

SEED="${WORKDIR}/seed"
cp -r "${REPO_ROOT}" "${SEED}"
rm -rf "${SEED}/.git"
git -C "${SEED}" init -q -b main
git -C "${SEED}" config user.email "ci@example.com"
git -C "${SEED}" config user.name "ci"
git -C "${SEED}" remote add origin "${BARE}"
git -C "${SEED}" add -A
git -C "${SEED}" commit -q -m "initial"
git -C "${SEED}" push -q origin main

CHECKOUT="${WORKDIR}/checkout"
git clone -q "${BARE}" "${CHECKOUT}"
git -C "${CHECKOUT}" config user.email "ci@example.com"
git -C "${CHECKOUT}" config user.name "ci"

# Push a second commit to the remote (a version bump, like a real release)
# so the checkout above is genuinely behind it -- otherwise
# update_available stays false and update.sh's notify logic is never
# reached at all, regardless of what this test is actually trying to
# check.
sed -i 's/VERSION = "[^"]*"/VERSION = "99.99.99"/' "${SEED}/abuseipdb_proxy.py"
git -C "${SEED}" add -A
git -C "${SEED}" commit -q -m "bump to 99.99.99 (test)"
git -C "${SEED}" push -q origin main

echo "=== Test 1: update.sh 'notified' is false with no binary installed ==="
reset_install_state
OUT="$(cd "${CHECKOUT}" && bash update.sh --check-only --json)"
echo "  ${OUT}"
if echo "${OUT}" | grep -q '"notified": false'; then
    ok "notified=false with no binary present"
else
    bad "expected notified=false with no binary present, got: ${OUT}"
fi

echo "=== Test 2: update.sh 'notified' is false with a binary but no backend configured ==="
reset_install_state
install -m 755 "${SEED}/abuseipdb_proxy.py" /usr/local/bin/abuseipdb_proxy.py
unset ABUSEIPDB_GOTIFY_URL ABUSEIPDB_NTFY_URL ABUSEIPDB_SLACK_WEBHOOK_URL \
      ABUSEIPDB_DISCORD_WEBHOOK_URL ABUSEIPDB_WEBHOOK_URL ABUSEIPDB_TELEGRAM_BOT_TOKEN \
      ABUSEIPDB_HOMEASSISTANT_URL ABUSEIPDB_MATRIX_HOMESERVER 2>/dev/null || true
OUT="$(cd "${CHECKOUT}" && bash update.sh --check-only --json)"
echo "  ${OUT}"
if echo "${OUT}" | grep -q '"notified": false'; then
    ok "notified=false with binary present but no backend configured (this is the bug this test guards against)"
else
    bad "expected notified=false with no backend configured, got: ${OUT} -- this is exactly the bug from CHANGELOG 3.1.1: the binary being executable was mistaken for a notification actually being sent"
fi

echo "=== Test 3: update.sh 'notified' is true with a binary and a backend configured ==="
reset_install_state
install -m 755 "${SEED}/abuseipdb_proxy.py" /usr/local/bin/abuseipdb_proxy.py
export ABUSEIPDB_GOTIFY_URL="http://127.0.0.1:1/unreachable"
export ABUSEIPDB_GOTIFY_TOKEN="test"
OUT="$(cd "${CHECKOUT}" && bash update.sh --check-only --json)"
unset ABUSEIPDB_GOTIFY_URL ABUSEIPDB_GOTIFY_TOKEN
echo "  ${OUT}"
if echo "${OUT}" | grep -q '"notified": true'; then
    ok "notified=true with a backend configured (delivery itself is fire-and-forget/best-effort, so this only means a send was attempted)"
else
    bad "expected notified=true with a backend configured, got: ${OUT}"
fi

echo "=== Test 4: install.sh keeps an existing key when re-run non-interactively ==="
reset_install_state
mkdir -p /etc/abuseipdb-proxy
echo "ABUSEIPDB_API_KEY=ci-test-key-12345" > /etc/abuseipdb-proxy/abuseipdb-proxy.env
chmod 600 /etc/abuseipdb-proxy/abuseipdb-proxy.env
set +e
(cd "${SEED}" && bash install.sh < /dev/null > "${WORKDIR}/install1.log" 2>&1)
INSTALL_EXIT=$?
set -e
cat "${WORKDIR}/install1.log"
if grep -q "^ABUSEIPDB_API_KEY=ci-test-key-12345$" /etc/abuseipdb-proxy/abuseipdb-proxy.env; then
    ok "existing key preserved after a non-interactive re-run"
else
    bad "existing key was not preserved after a non-interactive re-run (install exited ${INSTALL_EXIT})"
fi
if grep -q "Non-interactive run detected -- keeping the existing key" "${WORKDIR}/install1.log"; then
    ok "printed a clear message explaining the non-interactive default"
else
    bad "did not explain why the existing key was kept"
fi

echo "=== Test 5: install.sh fails cleanly (not silently) with no key and no TTY ==="
reset_install_state
set +e
(cd "${SEED}" && bash install.sh < /dev/null > "${WORKDIR}/install2.log" 2>&1)
INSTALL_EXIT=$?
set -e
cat "${WORKDIR}/install2.log"
if [[ "${INSTALL_EXIT}" -ne 0 ]]; then
    ok "exited non-zero as expected (no key, no TTY to prompt)"
else
    bad "expected a non-zero exit with no key configured and no TTY, got 0"
fi
if grep -q "isn't an" "${WORKDIR}/install2.log" && grep -q "interactive terminal" "${WORKDIR}/install2.log"; then
    ok "printed a clear, actionable error instead of silently dying inside \`read\`"
else
    bad "did not print the expected explanatory error message -- this is exactly the bug from CHANGELOG 3.1.1: a silent, unexplained set -e kill"
fi

reset_install_state

echo ""
echo "=== ${PASS} passed, ${FAIL} failed ==="
if [[ "${FAIL}" -ne 0 ]]; then
    exit 1
fi
