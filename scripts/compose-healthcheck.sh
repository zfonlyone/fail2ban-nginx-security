#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/etc/security-guard"
cd "$BASE_DIR"

log() { echo "$(date '+%F %T') [security-health] $*"; }

if ! docker info >/dev/null 2>&1; then
  log "docker daemon not ready"
  exit 1
fi

mapfile -t services < <(docker compose config --services 2>/dev/null || true)
if [ ${#services[@]} -eq 0 ]; then
  log "no services found"
  exit 0
fi

mapfile -t running_services < <(docker compose ps --status running --services 2>/dev/null || true)
mapfile -t exited_services < <(docker compose ps --status exited --services 2>/dev/null || true)

for svc in "${exited_services[@]}"; do
  [ -n "${svc}" ] || continue
  log "service exited: $svc -> restart"
  docker compose restart "$svc" >/dev/null 2>&1 || docker compose up -d "$svc" >/dev/null 2>&1 || true
done

for cid in $(docker compose ps -q 2>/dev/null); do
  [ -n "$cid" ] || continue
  hs="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo none)"
  if [ "$hs" = "unhealthy" ]; then
    svc="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' "$cid" 2>/dev/null || true)"
    if [ -n "$svc" ]; then
      log "service unhealthy: $svc -> restart"
      docker compose restart "$svc" >/dev/null 2>&1 || true
    fi
  fi
done

for svc in "${services[@]}"; do
  found=0
  for r in "${running_services[@]}"; do
    if [ "$svc" = "$r" ]; then
      found=1
      break
    fi
  done
  if [ $found -eq 0 ]; then
    log "service not running: $svc -> up"
    docker compose up -d "$svc" >/dev/null 2>&1 || docker compose up -d >/dev/null 2>&1 || true
  fi
done

log "health check done"
