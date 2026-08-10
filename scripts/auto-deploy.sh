#!/bin/bash
# Auto-deploy service for Centinela AI
# Rebuilds and restarts Docker services after system boot / reboot

LOG_FILE="/opt/centinela-ai/logs/auto-deploy.log"
mkdir -p /opt/centinela-ai/logs

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Centinela AI auto-deploy service..." >> "$LOG_FILE"

cd /opt/centinela-ai || exit 1

# Bring down services cleanly
docker compose down >> "$LOG_FILE" 2>&1

# Rebuild containers ensuring code updates are included
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Building containers..." >> "$LOG_FILE"
docker compose build >> "$LOG_FILE" 2>&1

# Start services
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting containers..." >> "$LOG_FILE"
docker compose up -d >> "$LOG_FILE" 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Auto-deploy completed successfully." >> "$LOG_FILE"
