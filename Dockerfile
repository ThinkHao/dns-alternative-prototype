FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DNS_ALT_API_HOST=0.0.0.0 \
    DNS_ALT_DNS_HOST=0.0.0.0 \
    DNS_ALT_API_PORT=8765 \
    DNS_ALT_DNS_PORT=15300 \
    DNS_ALT_DB_PATH=/data/dns-alternative-prototype.sqlite3

WORKDIR /app
LABEL org.opencontainers.image.source="https://github.com/ThinkHao/dns-alternative-prototype"
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home app \
    && mkdir -p /data \
    && chown app:app /data

COPY --chown=app:app server.py dns_runtime.py dnsdist_compiler.py index.html VERSION ./
USER app

EXPOSE 8765/tcp 15300/tcp 15300/udp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=2)"]
CMD ["python", "server.py"]
