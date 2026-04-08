FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="DevSecOps Demo App"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -M -s /sbin/nologin appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup app/ ./app/

RUN mkdir -p /app/logs && chown appuser:appgroup /app/logs

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host", "0.0.0.0", "--port", "8080"]
