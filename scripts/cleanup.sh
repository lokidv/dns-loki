#!/usr/bin/env bash
set -euo pipefail

# Cleanup script for dns-loki deployment
# Safely stops services and containers and removes installation files.
# Usage:
#   sudo bash scripts/cleanup.sh [--restore-resolved]
#
# Flags:
#   --restore-resolved   Re-enable systemd-resolved and restore DNS to system default.

RESTORE_RESOLVED=false
if [[ ${1:-} == "--restore-resolved" ]]; then
  RESTORE_RESOLVED=true
fi

is_active() { systemctl is-active --quiet "$1"; }
unit_exists() { systemctl list-unit-files | grep -q "^$1" || [[ -f "/etc/systemd/system/$1" ]]; }

log() { echo -e "[cleanup] $*"; }

log "Stopping agent and controller services if present..."
for SVC in dns-proxy-agent.service dns-proxy-controller.service; do
  if unit_exists "$SVC"; then
    systemctl stop "$SVC" || true
    systemctl disable "$SVC" || true
    rm -f "/etc/systemd/system/$SVC" || true
  fi
done
systemctl daemon-reload || true

# Bring down docker stacks
if command -v docker >/dev/null 2>&1; then
  if [[ -d /opt/dns-proxy/docker/dns ]]; then
    (cd /opt/dns-proxy/docker/dns && docker compose down -v || true)
  fi
  if [[ -d /opt/dns-proxy/docker/proxy ]]; then
    (cd /opt/dns-proxy/docker/proxy && docker compose down -v || true)
  fi
  # Force-remove known containers if still exist
  for C in coredns sniproxy; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${C}$"; then
      docker rm -f "$C" || true
    fi
  done
fi

# Optional: restore system DNS manager
if $RESTORE_RESOLVED; then
  if systemctl list-unit-files | grep -q '^systemd-resolved.service'; then
    log "Re-enabling systemd-resolved..."
    systemctl enable --now systemd-resolved || true
  fi
  # Try to restore resolv.conf symlink if broken
  if [[ ! -L /etc/resolv.conf && -f /run/systemd/resolve/stub-resolv.conf ]]; then
    log "Restoring /etc/resolv.conf to systemd stub..."
    mv /etc/resolv.conf /etc/resolv.conf.backup.$(date +%s) 2>/dev/null || true
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true
  fi
fi

# Remove installation directory
if [[ -d /opt/dns-proxy ]]; then
  log "Removing /opt/dns-proxy ..."
  rm -rf /opt/dns-proxy || true
fi

log "Cleanup complete."
