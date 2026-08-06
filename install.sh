#!/usr/bin/env bash
#
# Installer for the CrowdSec Smart AbuseIPDB Proxy
#
# Expects the following files in the same directory:
#   - abuseipdb_proxy.py
#   - abuseipdb-proxy.service
#   - abuseipdb.yaml
# Optional (enables the daily update-check timer if present):
#   - abuseipdb-proxy-update-check.service
#   - abuseipdb-proxy-update-check.timer
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_PATH="/usr/local/bin/abuseipdb_proxy.py"
SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy.service"
ENV_DIR="/etc/abuseipdb-proxy"
ENV_PATH="${ENV_DIR}/abuseipdb-proxy.env"
CACHE_DIR="/var/lib/abuseipdb-proxy"
NOTIF_PATH="/etc/crowdsec/notifications/abuseipdb.yaml"
PROFILES_PATH="/etc/crowdsec/profiles.yaml"
UPDATE_CHECK_SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy-update-check.service"
UPDATE_CHECK_TIMER_PATH="/etc/systemd/system/abuseipdb-proxy-update-check.timer"
VACUUM_SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy-vacuum.service"
VACUUM_TIMER_PATH="/etc/systemd/system/abuseipdb-proxy-vacuum.timer"
BACKUP_SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy-backup.service"
BACKUP_TIMER_PATH="/etc/systemd/system/abuseipdb-proxy-backup.timer"
RECONCILE_SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy-reconcile.service"
RECONCILE_TIMER_PATH="/etc/systemd/system/abuseipdb-proxy-reconcile.timer"

# --- Root check ----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g. with sudo)." >&2
    exit 1
fi

# --- Check prerequisites ---------------------------------------------------
for f in abuseipdb_proxy.py abuseipdb-proxy.service abuseipdb.yaml; do
    if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
        echo "Error: ${f} not found next to this script (${SCRIPT_DIR})." >&2
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 was not found. Please install it first." >&2
    exit 1
fi

if [[ ! -d /etc/crowdsec ]]; then
    echo "Warning: /etc/crowdsec not found. Is CrowdSec installed on this host?" >&2
fi

echo "== CrowdSec Smart AbuseIPDB Proxy - Installer =="
echo

# --- Ask for the API key ----------------------------------------------------
EXISTING_KEY=""
if [[ -f "${ENV_PATH}" ]]; then
    EXISTING_KEY=$(grep -E '^ABUSEIPDB_API_KEY=' "${ENV_PATH}" 2>/dev/null | cut -d'=' -f2- || true)
fi

if [[ -n "${EXISTING_KEY}" ]]; then
    echo "An API key was already found under ${ENV_PATH}."
    read -r -p "Keep the existing key? [Y/n] " KEEP_KEY
    KEEP_KEY="${KEEP_KEY:-Y}"
fi

if [[ "${KEEP_KEY:-n}" =~ ^[Yy]$ ]]; then
    API_KEY="${EXISTING_KEY}"
else
    read -r -s -p "Enter your AbuseIPDB API key (input hidden): " API_KEY
    echo
    if [[ -z "${API_KEY}" ]]; then
        echo "Error: no API key was entered." >&2
        exit 1
    fi
fi

# --- Install files -----------------------------------------------------------
echo "-> Copying proxy script to ${BIN_PATH}"
install -m 0755 "${SCRIPT_DIR}/abuseipdb_proxy.py" "${BIN_PATH}"

echo "-> Creating cache directory ${CACHE_DIR}"
mkdir -p "${CACHE_DIR}"
chmod 0700 "${CACHE_DIR}"

echo "-> Writing API key to ${ENV_PATH} (chmod 600)"
mkdir -p "${ENV_DIR}"
chmod 0700 "${ENV_DIR}"
cat > "${ENV_PATH}" <<EOF
ABUSEIPDB_API_KEY=${API_KEY}
EOF
chmod 0600 "${ENV_PATH}"

echo "-> Installing systemd service to ${SERVICE_PATH}"
install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy.service" "${SERVICE_PATH}"

echo "-> Installing CrowdSec notification to ${NOTIF_PATH}"
if [[ -d /etc/crowdsec/notifications ]]; then
    install -m 0644 "${SCRIPT_DIR}/abuseipdb.yaml" "${NOTIF_PATH}"
else
    echo "   Skipped: /etc/crowdsec/notifications does not exist." >&2
fi

# --- Enable the service -------------------------------------------------
echo "-> Enabling and (re)starting abuseipdb-proxy.service"
systemctl daemon-reload
systemctl enable abuseipdb-proxy.service
# 'restart' instead of 'start': if the service was already running (e.g.
# during an update), 'start' is a no-op and the old code keeps running.
systemctl restart abuseipdb-proxy.service

sleep 1
if systemctl is-active --quiet abuseipdb-proxy.service; then
    echo "   Service is running."
else
    echo "   Warning: service does not appear to be active. Check: journalctl -u abuseipdb-proxy.service" >&2
fi

# --- Reload CrowdSec --------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^crowdsec.service'; then
    echo "-> Reloading CrowdSec"
    systemctl reload crowdsec.service || echo "   Warning: 'systemctl reload crowdsec' failed, please check manually." >&2
fi

# --- Optional: daily update-check timer ----------------------------------
if [[ -f "${SCRIPT_DIR}/abuseipdb-proxy-update-check.service" && -f "${SCRIPT_DIR}/abuseipdb-proxy-update-check.timer" ]]; then
    echo
    TIMER_ALREADY_ENABLED=false
    if systemctl is-enabled --quiet abuseipdb-proxy-update-check.timer 2>/dev/null; then
        TIMER_ALREADY_ENABLED=true
    fi

    ENABLE_TIMER="n"
    if [[ "${TIMER_ALREADY_ENABLED}" == "true" ]]; then
        ENABLE_TIMER="y"  # already opted in previously, keep it that way across updates
    elif [[ -t 0 ]]; then
        read -r -p "Enable a daily timer that checks for proxy updates and notifies you (never auto-applies)? [y/N] " ENABLE_TIMER
    fi

    if [[ "${ENABLE_TIMER}" =~ ^[Yy]$ ]]; then
        echo "-> Installing update-check timer"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-update-check.service" "${UPDATE_CHECK_SERVICE_PATH}"
        # ExecStart must point at update.sh inside *this* checkout, which
        # varies per install, so rewrite the placeholder from the shipped unit.
        sed -i "s|^ExecStart=.*|ExecStart=${SCRIPT_DIR}/update.sh --check-only|" "${UPDATE_CHECK_SERVICE_PATH}"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-update-check.timer" "${UPDATE_CHECK_TIMER_PATH}"
        systemctl daemon-reload
        systemctl enable --now abuseipdb-proxy-update-check.timer
        echo "   Enabled. Status: systemctl status abuseipdb-proxy-update-check.timer"
    elif [[ "${TIMER_ALREADY_ENABLED}" == "false" ]]; then
        echo "   Skipped. Re-run install.sh anytime to add it, or set it up manually:"
        echo "     abuseipdb-proxy-update-check.service / .timer"
    fi
fi

# --- Optional: weekly SQLite vacuum timer ---------------------------------
# Only offered when the SQLite backend is actually in use (--vacuum is a
# no-op otherwise, so there's nothing to schedule for a JSON-cache install).
CACHE_BACKEND_IN_USE="$(grep -m1 '^ABUSEIPDB_CACHE_BACKEND=' "${ENV_PATH}" 2>/dev/null | cut -d= -f2-)"
if [[ -z "${CACHE_BACKEND_IN_USE}" ]]; then
    CACHE_BACKEND_IN_USE="sqlite"  # v2.0.0+ default when unset
fi
if [[ "${CACHE_BACKEND_IN_USE}" == "sqlite" \
      && -f "${SCRIPT_DIR}/abuseipdb-proxy-vacuum.service" && -f "${SCRIPT_DIR}/abuseipdb-proxy-vacuum.timer" ]]; then
    echo
    VACUUM_TIMER_ALREADY_ENABLED=false
    if systemctl is-enabled --quiet abuseipdb-proxy-vacuum.timer 2>/dev/null; then
        VACUUM_TIMER_ALREADY_ENABLED=true
    fi

    ENABLE_VACUUM_TIMER="n"
    if [[ "${VACUUM_TIMER_ALREADY_ENABLED}" == "true" ]]; then
        ENABLE_VACUUM_TIMER="y"
    elif [[ -t 0 ]]; then
        read -r -p "Enable a weekly timer that vacuums the SQLite cache to reclaim disk space? [y/N] " ENABLE_VACUUM_TIMER
    fi

    if [[ "${ENABLE_VACUUM_TIMER}" =~ ^[Yy]$ ]]; then
        echo "-> Installing vacuum timer"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-vacuum.service" "${VACUUM_SERVICE_PATH}"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-vacuum.timer" "${VACUUM_TIMER_PATH}"
        systemctl daemon-reload
        systemctl enable --now abuseipdb-proxy-vacuum.timer
        echo "   Enabled. Status: systemctl status abuseipdb-proxy-vacuum.timer"
    elif [[ "${VACUUM_TIMER_ALREADY_ENABLED}" == "false" ]]; then
        echo "   Skipped. Re-run install.sh anytime to add it, or run 'abuseipdb_proxy.py --vacuum' by hand whenever."
    fi
fi

# --- Optional: daily backup timer -----------------------------------------
if [[ -f "${SCRIPT_DIR}/abuseipdb-proxy-backup.service" && -f "${SCRIPT_DIR}/abuseipdb-proxy-backup.timer" ]]; then
    echo
    BACKUP_TIMER_ALREADY_ENABLED=false
    if systemctl is-enabled --quiet abuseipdb-proxy-backup.timer 2>/dev/null; then
        BACKUP_TIMER_ALREADY_ENABLED=true
    fi

    ENABLE_BACKUP_TIMER="n"
    if [[ "${BACKUP_TIMER_ALREADY_ENABLED}" == "true" ]]; then
        ENABLE_BACKUP_TIMER="y"
    elif [[ -t 0 ]]; then
        read -r -p "Enable a daily timer that backs up the cache (kept as portable JSON, last 14 by default)? [y/N] " ENABLE_BACKUP_TIMER
    fi

    if [[ "${ENABLE_BACKUP_TIMER}" =~ ^[Yy]$ ]]; then
        echo "-> Installing backup timer"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-backup.service" "${BACKUP_SERVICE_PATH}"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-backup.timer" "${BACKUP_TIMER_PATH}"
        systemctl daemon-reload
        systemctl enable --now abuseipdb-proxy-backup.timer
        echo "   Enabled. Status: systemctl status abuseipdb-proxy-backup.timer"
        echo "   Backups land in \$(dirname of your cache file)/backups — set ABUSEIPDB_BACKUP_RETENTION to change how many are kept."
    elif [[ "${BACKUP_TIMER_ALREADY_ENABLED}" == "false" ]]; then
        echo "   Skipped. Re-run install.sh anytime to add it, or run 'abuseipdb_proxy.py --backup' by hand whenever."
    fi
fi

# --- Optional: hourly CrowdSec decision reconciliation timer --------------
# Only offered when a bouncer key is already configured — without one,
# --reconcile just errors out immediately. Get one with
# 'cscli bouncers add <name>' on the CrowdSec host, add
# ABUSEIPDB_CROWDSEC_BOUNCER_KEY to the env file, then re-run install.sh.
BOUNCER_KEY_SET="$(grep -m1 '^ABUSEIPDB_CROWDSEC_BOUNCER_KEY=' "${ENV_PATH}" 2>/dev/null | cut -d= -f2-)"
if [[ -n "${BOUNCER_KEY_SET}" \
      && -f "${SCRIPT_DIR}/abuseipdb-proxy-reconcile.service" && -f "${SCRIPT_DIR}/abuseipdb-proxy-reconcile.timer" ]]; then
    echo
    RECONCILE_TIMER_ALREADY_ENABLED=false
    if systemctl is-enabled --quiet abuseipdb-proxy-reconcile.timer 2>/dev/null; then
        RECONCILE_TIMER_ALREADY_ENABLED=true
    fi

    ENABLE_RECONCILE_TIMER="n"
    if [[ "${RECONCILE_TIMER_ALREADY_ENABLED}" == "true" ]]; then
        ENABLE_RECONCILE_TIMER="y"
    elif [[ -t 0 ]]; then
        read -r -p "Enable an hourly timer that reconciles against CrowdSec's active decisions (catches reports missed during downtime)? [y/N] " ENABLE_RECONCILE_TIMER
    fi

    if [[ "${ENABLE_RECONCILE_TIMER}" =~ ^[Yy]$ ]]; then
        echo "-> Installing reconciliation timer"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-reconcile.service" "${RECONCILE_SERVICE_PATH}"
        install -m 0644 "${SCRIPT_DIR}/abuseipdb-proxy-reconcile.timer" "${RECONCILE_TIMER_PATH}"
        systemctl daemon-reload
        systemctl enable --now abuseipdb-proxy-reconcile.timer
        echo "   Enabled. Status: systemctl status abuseipdb-proxy-reconcile.timer"
    elif [[ "${RECONCILE_TIMER_ALREADY_ENABLED}" == "false" ]]; then
        echo "   Skipped. Re-run install.sh anytime to add it, or run 'abuseipdb_proxy.py --reconcile' by hand whenever."
    fi
fi

# --- Note about profiles.yaml --------------------------------------------
echo
if [[ -f "${PROFILES_PATH}" ]] && grep -q "abuseipdb_default" "${PROFILES_PATH}"; then
    echo "Note: 'abuseipdb_default' is already referenced in ${PROFILES_PATH}."
else
    echo "IMPORTANT: The notification only becomes active once it is referenced in"
    echo "${PROFILES_PATH} under:"
    echo "  notifications:"
    echo "    - abuseipdb_default"
    echo "This script intentionally does NOT do that automatically, since"
    echo "profiles.yaml layouts vary a lot between setups."
fi

echo
echo "Done. View logs with: journalctl -u abuseipdb-proxy.service -f"
