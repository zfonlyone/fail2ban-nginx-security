#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/etc/security-guard"
UNIT_PREFIX="security-guard"
HEALTH_SCRIPT="/usr/local/bin/security-guard-compose-healthcheck"

if [ "${EUID}" -ne 0 ]; then
  echo "please run as root"
  exit 1
fi

if [ ! -f "$HEALTH_SCRIPT" ]; then
  echo "missing health script: $HEALTH_SCRIPT"
  exit 1
fi

chmod +x "$HEALTH_SCRIPT"

cat > "/etc/systemd/system/${UNIT_PREFIX}-compose.service" <<EOF_UNIT
[Unit]
Description=Security Guard Compose Stack
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=${BASE_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF_UNIT

cat > "/etc/systemd/system/${UNIT_PREFIX}-healthcheck.service" <<EOF_UNIT
[Unit]
Description=Security Guard Compose Health Check
After=${UNIT_PREFIX}-compose.service

[Service]
Type=oneshot
ExecStart=${HEALTH_SCRIPT}
EOF_UNIT

cat > "/etc/systemd/system/${UNIT_PREFIX}-healthcheck.timer" <<EOF_UNIT
[Unit]
Description=Run Security Guard health check every 5 minutes

[Timer]
OnBootSec=2min
OnCalendar=*:0/5
AccuracySec=10s
Unit=${UNIT_PREFIX}-healthcheck.service
Persistent=true

[Install]
WantedBy=timers.target
EOF_UNIT

systemctl daemon-reload
systemctl enable --now "${UNIT_PREFIX}-compose.service"
systemctl enable --now "${UNIT_PREFIX}-healthcheck.timer"

echo "installed: ${UNIT_PREFIX}-compose.service + ${UNIT_PREFIX}-healthcheck.timer"
