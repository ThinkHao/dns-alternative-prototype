FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DNS_ALT_API_HOST=0.0.0.0 \
    DNS_ALT_DNS_HOST=0.0.0.0 \
    DNS_ALT_API_PORT=8765 \
    DNS_ALT_DNS_PORT=15300 \
    DNS_ALT_DB_PATH=/data/dns-alternative-prototype.sqlite3

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home app \
    && mkdir -p /data \
    && chown app:app /data

COPY --chown=app:app server.py dns_runtime.py dnsdist_compiler.py index.html ./
USER app

EXPOSE 8765/tcp 15300/tcp 15300/udp
VOLUME ["/data"]
CMD ["python", "server.py"]
