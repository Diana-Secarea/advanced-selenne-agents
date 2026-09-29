FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY selenne_agents ./selenne_agents
COPY frontend ./frontend
ENV FRONTEND_DIR=/app/frontend

RUN useradd --system --uid 10001 selenne \
 && mkdir -p /var/log/selenne-agents && chown selenne /var/log/selenne-agents
USER selenne
# Own JSON log files (ingest.json / console.json) — a named volume in compose,
# never a directory Selenne's Wazuh collector reads.
ENV LOG_DIR=/var/log/selenne-agents

EXPOSE 4317 4318
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('INGEST_HTTP_PORT','4318'), timeout=2)"

CMD ["python", "-m", "selenne_agents.ingest"]
