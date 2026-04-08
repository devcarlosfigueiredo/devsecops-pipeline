FROM python:3.12-alpine3.19 AS builder

LABEL stage="builder"
LABEL maintainer="security@example.com"

WORKDIR /build

RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
       --prefix=/install \
       -r requirements.txt

FROM python:3.12-alpine3.19 AS runtime

LABEL org.opencontainers.image.title="DevSecOps Demo App"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

RUN addgroup -g 10001 -S appgroup \
    && adduser -u 10001 -S -G appgroup -H -D appuser

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=appuser:appgroup app/ ./app/

RUN mkdir -p /app/logs && chown appuser:appgroup /app/logs

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host", "0.0.0.0", "--port", "8080"]
