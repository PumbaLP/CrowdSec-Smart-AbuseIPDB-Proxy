#!/usr/bin/env bash
#
# Uninstaller for the CrowdSec Smart AbuseIPDB Proxy
#
set -euo pipefail

BIN_PATH="/usr/local/bin/abuseipdb_proxy.py"
SERVICE_PATH="/etc/systemd/system/abuseipdb-proxy.service"
ENV_DIR="/etc/abuseipdb-proxy"
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

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g. with sudo)." >&2
    exit 1
fi

AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) AUTO_YES=true ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

echo "== CrowdSec Smart AbuseIPDB Proxy - Uninstaller =="
echo
echo "This will remove:"
echo "  - ${SERVICE_PATH}"
echo "  - ${UPDATE_CHECK_SERVICE_PATH} / ${UPDATE_CHECK_TIMER_PATH} (if enabled)"
echo "  - ${VACUUM_SERVICE_PATH} / ${VACUUM_TIMER_PATH} (if enabled)"
echo "  - ${BACKUP_SERVICE_PATH} / ${BACKUP_TIMER_PATH} (if enabled)"
echo "  - ${RECONCILE_SERVICE_PATH} / ${RECONCILE_TIMER_PATH} (if enabled)"
echo "  - ${BIN_PATH}"
echo "  - ${ENV_DIR} (includes your AbuseIPDB API key)"
echo "  - ${CACHE_DIR} (includes report history / pending retries)"
echo "  - ${NOTIF_PATH}"
echo

KEEP_DATA="n"
if [[ "${AUTO_YES}" != "true" ]]; then
    if [[ -d "${ENV_DIR}" || -d "${CACHE_DIR}" ]]; then
        read -r -p "Keep the API key and cache data in case you reinstall later? [y/N] " KEEP_DATA
        KEEP_DATA="${KEEP_DATA:-N}"
    fi

    read -r -p "Proceed with uninstall? [y/N] " CONFIRM
    CONFIRM="${CONFIRM:-N}"
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        echo "Aborted, nothing was changed."
        exit 0
    fi
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^abuseipdb-proxy.service'; then
    echo "-> Stopping and disabling the service"
    systemctl disable --now abuseipdb-proxy.service 2>/dev/null || true
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^abuseipdb-proxy-update-check.timer'; then
    echo "-> Stopping and disabling the update-check timer"
    systemctl disable --now abuseipdb-proxy-update-check.timer 2>/dev/null || true
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^abuseipdb-proxy-vacuum.timer'; then
    echo "-> Stopping and disabling the vacuum timer"
    systemctl disable --now abuseipdb-proxy-vacuum.timer 2>/dev/null || true
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^abuseipdb-proxy-backup.timer'; then
    echo "-> Stopping and disabling the backup timer"
    systemctl disable --now abuseipdb-proxy-backup.timer 2>/dev/null || true
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^abuseipdb-proxy-reconcile.timer'; then
    echo "-> Stopping and disabling the reconciliation timer"
    systemctl disable --now abuseipdb-proxy-reconcile.timer 2>/dev/null || true
fi

echo "-> Removing systemd unit(s)"
rm -f "${SERVICE_PATH}" "${UPDATE_CHECK_SERVICE_PATH}" "${UPDATE_CHECK_TIMER_PATH}" \
      "${VACUUM_SERVICE_PATH}" "${VACUUM_TIMER_PATH}" \
      "${BACKUP_SERVICE_PATH}" "${BACKUP_TIMER_PATH}" \
      "${RECONCILE_SERVICE_PATH}" "${RECONCILE_TIMER_PATH}"
systemctl daemon-reload

echo "-> Removing proxy script"
rm -f "${BIN_PATH}"

echo "-> Removing CrowdSec notification"
rm -f "${NOTIF_PATH}"

if [[ "${KEEP_DATA}" =~ ^[Yy]$ ]]; then
    echo "-> Keeping ${ENV_DIR} and ${CACHE_DIR} as requested"
else
    echo "-> Removing ${ENV_DIR} and ${CACHE_DIR}"
    rm -rf "${ENV_DIR}"
    rm -rf "${CACHE_DIR}"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^crowdsec.service'; then
    echo "-> Reloading CrowdSec"
    systemctl reload crowdsec.service || echo "   Warning: 'systemctl reload crowdsec' failed, please check manually." >&2
fi

echo
if [[ -f "${PROFILES_PATH}" ]] && grep -q "abuseipdb_default" "${PROFILES_PATH}"; then
    echo "REMINDER: '${PROFILES_PATH}' still references 'abuseipdb_default' under 'notifications:'."
    echo "Remove that entry manually if you don't plan to reinstall, otherwise CrowdSec"
    echo "will log delivery errors for a notification target that no longer exists."
fi

echo
echo "Uninstall complete."
