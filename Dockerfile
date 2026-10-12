FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends fail2ban iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

COPY fail2ban/jail.local /etc/fail2ban/jail.local
COPY fail2ban/uvicorn-flood.conf /etc/fail2ban/filter.d/uvicorn-flood.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8001
ENTRYPOINT ["/entrypoint.sh"]