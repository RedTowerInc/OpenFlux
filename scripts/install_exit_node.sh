#!/usr/bin/env bash
set -euo pipefail

# OpenFlux exit-node installer for a dedicated Debian/Ubuntu VPS.
# Usage:
#   sudo bash install_exit_node.sh 'https://disk.yandex.ru/i/SHARE_ID'
#
# The same public Yandex Docs URL must be configured in the Android client.
# This first-test installer uses a host-wide TCP RST drop while the service runs.
# Use only on a dedicated test VPS. Later we will replace this with a scoped
# network namespace / dedicated egress IP setup.

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash $0 'YANDEX_URL'" >&2
  exit 1
fi

YANDEX_URL="${1:-}"
if [[ -z "$YANDEX_URL" ]]; then
  echo "Usage: sudo bash $0 'https://disk.yandex.ru/i/...'" >&2
  exit 1
fi

case "$YANDEX_URL" in
  http://*|https://*) ;;
  *) echo "Yandex URL must start with http:// or https://" >&2; exit 1 ;;
esac

INSTALL_DIR=/opt/openflux
BIN=/usr/local/bin/openflux
ENV_DIR=/etc/openflux
ENV_FILE=$ENV_DIR/exit-node.env
SERVICE=/etc/systemd/system/openflux-exit.service
REPO=https://github.com/RedTowerInc/OpenFlux.git
BRANCH=openflux-android

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates git iptables golang-go

mkdir -p "$INSTALL_DIR" "$ENV_DIR"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --depth=1 origin "$BRANCH"
  git -C "$INSTALL_DIR" checkout -B "$BRANCH" FETCH_HEAD
else
  rm -rf "$INSTALL_DIR"
  git clone --depth=1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Prefer distro Go when sufficiently new; otherwise install the official toolchain
# requested by go.mod through Go's automatic toolchain mechanism.
export GOTOOLCHAIN=auto
go build -o "$BIN" .
chmod 0755 "$BIN"

# EnvironmentFile treats everything after '=' as the value. Public Yandex share
# URLs do not contain shell secrets, but keep the file root-only anyway.
printf 'YANDEX_URL=%s\n' "$YANDEX_URL" > "$ENV_FILE"
chmod 0600 "$ENV_FILE"

cat > "$SERVICE" <<'EOF'
[Unit]
Description=OpenFlux exit node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/openflux/exit-node.env
# Dedicated-test-VPS fallback. The rule exists only while this service runs.
ExecStartPre=/bin/sh -c '/usr/sbin/iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || /usr/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP'
ExecStart=/usr/local/bin/openflux --exit-node --transport yandex --url ${YANDEX_URL} --debug
ExecStopPost=/bin/sh -c '/usr/sbin/iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null && /usr/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP || true'
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now openflux-exit.service
sleep 2

echo
echo '=== OpenFlux exit-node status ==='
systemctl --no-pager --full status openflux-exit.service || true
echo
echo 'Live logs:'
echo '  sudo journalctl -u openflux-exit -f'
echo
echo 'Stop:'
echo '  sudo systemctl stop openflux-exit'
