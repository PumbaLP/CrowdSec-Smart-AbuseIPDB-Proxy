#!/usr/bin/env bash
#
# Update helper for the CrowdSec Smart AbuseIPDB Proxy.
#
# Checks for new commits on origin/main, shows what changed (including the
# relevant CHANGELOG.md section if the version bumped), then pulls and
# re-runs install.sh. Safe to run repeatedly — does nothing if already
# up to date.
#
# --check-only: only checks, applies nothing, sends a notification via
#               the configured alerting backend if an update is found.
# --json:       machine-readable output, for use with --check-only from
#               your own tooling (Home Assistant, a dashboard, ...)
#               instead of / in addition to the notification backend.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BIN_PATH="/usr/local/bin/abuseipdb_proxy.py"

AUTO_YES=false
CHECK_ONLY=false
JSON_OUTPUT=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) AUTO_YES=true ;;
        --check-only) CHECK_ONLY=true ;;
        --json) JSON_OUTPUT=true ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

if [[ "${JSON_OUTPUT}" == "true" && "${CHECK_ONLY}" != "true" ]]; then
    echo "Error: --json is only supported together with --check-only." >&2
    exit 1
fi

# Prints an informational line, unless --json was requested (in which
# case stdout is reserved for the single JSON result object at the end).
info() {
    if [[ "${JSON_OUTPUT}" != "true" ]]; then
        echo "$@"
    fi
}

# Emits the final --json result and exits. All fields are always present
# so callers don't have to special-case a missing key.
emit_json_result() {
    local update_available="$1" current_version="$2" new_version="$3" commit_count="$4" notified="$5"
    python3 - "$update_available" "$current_version" "$new_version" "$commit_count" "$notified" << 'PYEOF'
import json
import sys

update_available, current_version, new_version, commit_count, notified = sys.argv[1:6]
print(json.dumps({
    "update_available": update_available == "true",
    "current_version": current_version or None,
    "new_version": new_version or None,
    "commit_count": int(commit_count) if commit_count else 0,
    "notified": notified == "true",
}))
PYEOF
    exit 0
}

# Best-effort notification helper for --check-only. Reuses whatever
# alerting backend (Gotify/ntfy/webhook) is already configured for the
# proxy itself, via the installed binary's --notify flag. Never fails the
# script — a missing/unconfigured backend just means no notification.
notify_update_available() {
    local msg="$1"
    if [[ -x "${BIN_PATH}" ]]; then
        "${BIN_PATH}" --notify "${msg}" --notify-priority normal >/dev/null 2>&1 || true
    fi
}

if [[ ! -d .git ]]; then
    echo "Error: ${SCRIPT_DIR} is not a git checkout. Clone the repo with git instead of downloading a zip." >&2
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "Error: git is not installed." >&2
    exit 1
fi

# --- Refuse to clobber local changes --------------------------------------
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: this checkout has local changes (git status is not clean)." >&2
    echo "Commit, stash, or discard them first, then re-run this script." >&2
    git status --short >&2
    exit 1
fi

info "== CrowdSec Smart AbuseIPDB Proxy - Update =="
info

info "-> Fetching origin..."
git fetch --quiet origin

CURRENT_REF="$(git rev-parse HEAD)"
REMOTE_REF="$(git rev-parse origin/main)"
CURRENT_VERSION="$(grep -m1 '^VERSION = ' abuseipdb_proxy.py 2>/dev/null | sed -E 's/VERSION = "(.*)"/\1/' || true)"

if [[ "${CURRENT_REF}" == "${REMOTE_REF}" ]]; then
    info "Already up to date."
    if [[ -x "${BIN_PATH}" ]]; then
        INSTALLED_VERSION="$("${BIN_PATH}" --version 2>/dev/null | awk '{print $NF}' || true)"
        [[ -n "${INSTALLED_VERSION}" ]] && info "Installed version: ${INSTALLED_VERSION}"
    fi
    if [[ "${JSON_OUTPUT}" == "true" ]]; then
        emit_json_result "false" "${CURRENT_VERSION}" "" "0" "false"
    fi
    exit 0
fi

COMMIT_COUNT="$(git rev-list "${CURRENT_REF}..${REMOTE_REF}" --count)"
info "-> ${COMMIT_COUNT} new commit(s) available:"
info
if [[ "${JSON_OUTPUT}" != "true" ]]; then
    git log --oneline "${CURRENT_REF}..${REMOTE_REF}"
    echo
fi

# --- Detect a version bump and show the matching CHANGELOG section --------
OLD_VERSION="${CURRENT_VERSION}"
NEW_VERSION="$(git show "origin/main:abuseipdb_proxy.py" 2>/dev/null | grep -m1 '^VERSION = ' | sed -E 's/VERSION = "(.*)"/\1/' || true)"

if [[ -n "${NEW_VERSION}" && "${OLD_VERSION}" != "${NEW_VERSION}" ]]; then
    info "Version change: ${OLD_VERSION:-unknown} -> ${NEW_VERSION}"
    info
    if [[ "${JSON_OUTPUT}" != "true" ]]; then
        TMP_CHANGELOG="$(mktemp)"
        trap 'rm -f "${TMP_CHANGELOG}"' EXIT
        git show "origin/main:CHANGELOG.md" > "${TMP_CHANGELOG}" 2>/dev/null || true
        if [[ -s "${TMP_CHANGELOG}" ]]; then
            python3 - "${NEW_VERSION}" "${TMP_CHANGELOG}" << 'PYEOF'
import re
import sys

version = sys.argv[1]
changelog_path = sys.argv[2]
with open(changelog_path) as f:
    content = f.read()
pattern = (
    r"^## \[" + re.escape(version) + r"\](?: - (?P<subtitle>[^\n]*))?\n"
    r"(?P<body>.*?)(?=\n## \[|\Z)"
)
match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
if match:
    subtitle = match.group("subtitle")
    print(f"--- v{version}" + (f" - {subtitle}" if subtitle else "") + " ---")
    print(match.group("body").strip())
else:
    print(f"(No CHANGELOG.md entry found for {version}.)")
PYEOF
        fi
        echo
    fi
fi

if [[ "${CHECK_ONLY}" == "true" ]]; then
    NOTIFIED="false"
    [[ -x "${BIN_PATH}" ]] && NOTIFIED="true"

    if [[ -n "${NEW_VERSION}" && "${OLD_VERSION}" != "${NEW_VERSION}" ]]; then
        info "Update available: ${OLD_VERSION:-unknown} -> ${NEW_VERSION}"
        notify_update_available "Update to v${NEW_VERSION} available. Run update.sh to apply it."
    else
        info "Update available (${COMMIT_COUNT} new commit(s)), no version bump detected."
        notify_update_available "An update is available (${COMMIT_COUNT} new commit(s)). Run update.sh to apply it."
    fi
    info "Nothing was changed (--check-only). Run without --check-only to apply."

    if [[ "${JSON_OUTPUT}" == "true" ]]; then
        emit_json_result "true" "${OLD_VERSION}" "${NEW_VERSION}" "${COMMIT_COUNT}" "${NOTIFIED}"
    fi
    exit 0
fi

if [[ "${AUTO_YES}" != "true" ]]; then
    read -r -p "Pull these changes and re-run install.sh now? [y/N] " CONFIRM
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        echo "Aborted. Nothing was changed."
        exit 0
    fi
fi

echo "-> Pulling..."
git merge --ff-only origin/main

echo "-> Running install.sh..."
if [[ $EUID -eq 0 ]]; then
    ./install.sh
else
    sudo ./install.sh
fi

echo
echo "Update complete."
