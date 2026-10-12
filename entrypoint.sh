#!/bin/bash
set -e
mkdir -p /var/log/app /var/run/fail2ban
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid
touch /var/log/app/access.log /var/log/fail2ban.log

uvicorn app.main:app --host 0.0.0.0 --port 8001 >> /var/log/app/access.log 2>&1 &

sleep 1
fail2ban-client -x start

echo "[dashboard-backend] uvicorn + fail2ban corriendo. Siguiendo el log de fail2ban..."
exec tail -F /var/log/fail2ban.log