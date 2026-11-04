#!/usr/bin/env bash
# Dosya Yolu: REPO_ROOT/tools/test-service-systemd-ci.sh
# Amac: GitHub-hosted Linux runner'inda izole systemd servis yasam dongusu
# Modul - FileType: Tests - Bash
# Version: 0.3.1
# Aciklama: Start/stop/restart, staged upgrade/rollback, cleanup; kurulum yok
# Bagimli Oldugu Katman: Tool | Service | Config

set -Eeuo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
    echo "Live systemd test is restricted to GitHub-hosted CI." >&2
    exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
    echo "Linux runner does not provide a running systemd manager." >&2
    exit 1
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_bin="$repo/target/release/turkuazav-service"
template="$repo/deploy/service/turkuazav-preview.service"
[[ -f "$source_bin" && -f "$template" ]] || {
    echo "Missing service executable or unit template." >&2
    exit 1
}

unit="turkuazav-preview-ci-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}.service"
if sudo systemctl list-unit-files --all --no-legend "$unit" | grep -Fq "$unit"; then
    echo "Refusing to change a pre-existing unit: $unit" >&2
    exit 1
fi

# /run may be mounted noexec on hosted runners. Stage the executable
# within a root-owned executable filesystem; the entire fixture is removed
# by the EXIT trap and no installed service is modified.
sandbox="$(sudo mktemp -d /usr/local/bin/turkuazav-ci.XXXXXXXX)"
rendered="$(mktemp)"
created=0
cleanup() {
    local result=$?
    trap - EXIT
    if (( created == 1 )); then
        sudo systemctl stop "$unit" >/dev/null 2>&1 || true
        sudo rm -f -- "/run/systemd/system/$unit"
        sudo systemctl daemon-reload >/dev/null 2>&1 || true
        sudo systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    fi
    rm -f -- "$rendered"
    sudo rm -rf -- "$sandbox"
    exit "$result"
}
trap cleanup EXIT

sudo chmod 0755 "$sandbox"
sudo install -m 0555 "$source_bin" "$sandbox/turkuazav-service"
sudo install -d -m 0755 "$sandbox/watched"
printf 'safe sample' | sudo tee "$sandbox/watched/sample.txt" >/dev/null
sudo chmod 0444 "$sandbox/watched/sample.txt"
sudo chmod 0555 "$sandbox/watched"
sudo chmod 0755 "$sandbox"
printf 'TURKUAZ_WATCH_ROOT=%s\nTURKUAZ_INTERVAL_SECONDS=1\n' "$sandbox/watched" |
    sudo tee "$sandbox/preview.env" >/dev/null
sudo chmod 0644 "$sandbox/preview.env"

test_user="$(id -un)"
test_group="$(id -gn)"
# Verify actual unprivileged execution, not just Unix mode bits (noexec
# mount or inaccessible parent would otherwise fail in systemd later).
if ! sudo -u "$test_user" "$sandbox/turkuazav-service" --once "$sandbox/watched" 1 >/dev/null; then
    echo "Service executable cannot run from the isolated CI fixture." >&2
    exit 1
fi
sed \
    -e "s|^User=turkuazav$|User=$test_user|" \
    -e "s|^Group=turkuazav$|Group=$test_group|" \
    -e "s|^EnvironmentFile=/etc/turkuazav/preview.env$|EnvironmentFile=$sandbox/preview.env|" \
    -e "s|^ExecStart=/usr/local/libexec/turkuazav-service |ExecStart=$sandbox/turkuazav-service |" \
    -e "s|^RestartSec=10s$|RestartSec=1s|" \
    "$template" > "$rendered"

sudo install -m 0644 "$rendered" "/run/systemd/system/$unit"
created=1
sudo systemd-analyze verify "/run/systemd/system/$unit"
sudo systemctl daemon-reload
sudo systemctl start "$unit"

deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
    state="$(sudo systemctl show "$unit" -p ActiveState --value)"
    pid="$(sudo systemctl show "$unit" -p MainPID --value)"
    if [[ "$state" == "active" && "$pid" =~ ^[1-9][0-9]*$ ]]; then
        break
    fi
    sleep 0.2
done
[[ "$state" == active && "$pid" =~ ^[1-9][0-9]*$ ]] || {
    sudo journalctl -u "$unit" --no-pager -n 20 || true
    echo "systemd preview service did not become active." >&2
    exit 1
}
[[ "$(sudo systemctl show "$unit" -p User --value)" == "$test_user" ]]
[[ "$(sudo systemctl show "$unit" -p NoNewPrivileges --value)" == yes ]]
[[ "$(sudo systemctl show "$unit" -p ProtectSystem --value)" == strict ]]
[[ "$(sudo systemctl show "$unit" -p Restart --value)" == on-failure ]]
echo 'RUST_SYSTEMD_LIVE_START=PASS'

# Kill only the fixture unit's main process to exercise Restart=on-failure.
sudo systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
restarted=0
deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
    state="$(sudo systemctl show "$unit" -p ActiveState --value)"
    current_pid="$(sudo systemctl show "$unit" -p MainPID --value)"
    count="$(sudo systemctl show "$unit" -p NRestarts --value)"
    if [[ "$state" == active && "$current_pid" =~ ^[1-9][0-9]*$ &&
          "$current_pid" != "$pid" && "$count" =~ ^[1-9][0-9]*$ ]]; then
        restarted=1
        break
    fi
    sleep 0.2
done
if (( restarted != 1 )); then
    sudo journalctl -u "$unit" --no-pager -n 20 || true
    echo "systemd preview service did not restart after a process crash." >&2
    exit 1
fi
echo 'RUST_SYSTEMD_CRASH_RECOVERY=PASS'

sudo systemctl stop "$unit"
state="$(sudo systemctl show "$unit" -p ActiveState --value)"
[[ "$state" == inactive ]] || {
    echo "systemd stop did not transition service to inactive." >&2
    exit 1
}
echo 'RUST_SYSTEMD_LIVE_STOP=PASS'

# @dev-id TAV-SYSTEMD-UPGRADE-010
# @purpose Test versioned, offline binary staging and rollback on this run's
# temporary unit only. This does NOT install or upgrade a production service.
trusted_hash="$(sha256sum "$source_bin" | awk '{print $1}')"
upgrade_binary="$sandbox/turkuazav-service-v2"
sudo install -m 0555 "$source_bin" "$upgrade_binary"
[[ "$(sudo sha256sum "$upgrade_binary" | awk '{print $1}')" == "$trusted_hash" ]] || {
    echo "Staged systemd binary did not match the trusted fixture." >&2
    exit 1
}

upgrade_unit="$(mktemp)"
sed "s|$sandbox/turkuazav-service --foreground|$upgrade_binary --foreground|" \
    "$rendered" > "$upgrade_unit"
grep -Fq "ExecStart=$upgrade_binary --foreground" "$upgrade_unit" || {
    echo "systemd upgrade unit was not rendered correctly." >&2
    exit 1
}
sudo install -m 0644 "$upgrade_unit" "/run/systemd/system/$unit"
rm -f -- "$upgrade_unit"
sudo systemd-analyze verify "/run/systemd/system/$unit"
sudo systemctl daemon-reload
sudo systemctl start "$unit"
deadline=$((SECONDS + 30))
upgraded=0
while (( SECONDS < deadline )); do
    state="$(sudo systemctl show "$unit" -p ActiveState --value)"
    current_pid="$(sudo systemctl show "$unit" -p MainPID --value)"
    if [[ "$state" == active && "$current_pid" =~ ^[1-9][0-9]*$ ]]; then
        active_binary="$(sudo readlink -f "/proc/$current_pid/exe" || true)"
        if [[ "$active_binary" == "$upgrade_binary" ]]; then
            upgraded=1
            break
        fi
    fi
    sleep 0.2
done
[[ "$upgraded" == 1 ]] || { echo "systemd upgrade did not run staged binary." >&2; exit 1; }
sudo systemctl stop "$unit"
echo 'RUST_SYSTEMD_OFFLINE_UPGRADE=PASS'

# Negative staging: a corrupted candidate cannot mutate the unit or run.
bad_binary="$sandbox/turkuazav-service-tampered"
printf 'bad' | sudo tee "$bad_binary" >/dev/null
[[ "$(sudo sha256sum "$bad_binary" | awk '{print $1}')" != "$trusted_hash" ]] || {
    echo "Corrupt candidate unexpectedly passed the hash gate." >&2
    exit 1
}
sudo rm -f -- "$bad_binary"
[[ "$(sudo systemctl show "$unit" -p ExecStart --value)" == *"$upgrade_binary"* ]] || {
    echo "Rejected candidate unexpectedly changed the systemd unit." >&2
    exit 1
}
echo 'RUST_SYSTEMD_TAMPER_REJECTED=PASS'

# Restore and execute the original verified configuration before cleanup.
sudo install -m 0644 "$rendered" "/run/systemd/system/$unit"
sudo systemd-analyze verify "/run/systemd/system/$unit"
sudo systemctl daemon-reload
sudo systemctl start "$unit"
deadline=$((SECONDS + 30))
restored=0
while (( SECONDS < deadline )); do
    state="$(sudo systemctl show "$unit" -p ActiveState --value)"
    current_pid="$(sudo systemctl show "$unit" -p MainPID --value)"
    if [[ "$state" == active && "$current_pid" =~ ^[1-9][0-9]*$ ]]; then
        active_binary="$(sudo readlink -f "/proc/$current_pid/exe" || true)"
        if [[ "$active_binary" == "$sandbox/turkuazav-service" ]]; then
            restored=1
            break
        fi
    fi
    sleep 0.2
done
[[ "$restored" == 1 ]] || { echo "systemd rollback did not restore the original binary." >&2; exit 1; }
sudo systemctl stop "$unit"
[[ "$(sudo systemctl show "$unit" -p ActiveState --value)" == inactive ]] || {
    echo "systemd rollback service did not stop." >&2
    exit 1
}
echo 'RUST_SYSTEMD_OFFLINE_ROLLBACK=PASS'
