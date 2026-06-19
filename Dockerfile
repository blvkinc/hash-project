FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FIM_DATABASE_PATH=/app/data/file_monitor.db \
    FIM_MEMPALACE_PATH=/app/data/.mempalace_fim

WORKDIR /app

RUN addgroup --system integrityguard \
    && adduser --system --ingroup integrityguard integrityguard \
    && mkdir -p /app/data

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY web ./web
COPY README.md ./

RUN chown -R integrityguard:integrityguard /app

USER integrityguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()"

CMD ["python", "-m", "uvicorn", "core.api:app", "--host", "0.0.0.0", "--port", "8000"]
