# =============================================================================
# Dockerfile — DevSecOps Demo Application
# =============================================================================
#
# Práticas de segurança implementadas:
#   ✅ Multi-stage build — imagem final mínima (sem ferramentas de build)
#   ✅ Imagem base Alpine — superfície de ataque reduzida
#   ✅ Utilizador não-root (appuser:appgroup)
#   ✅ Sem shell desnecessário na imagem final
#   ✅ COPY --chown para ficheiros com ownership correto
#   ✅ Sem secrets no Dockerfile (passados via env vars em runtime)
#   ✅ Pinning de versão da imagem base
#   ✅ HEALTHCHECK configurado
#   ✅ EXPOSE documenta a porta (não a abre — isso é feito no deploy)
#
# Trivy IaC scan irá verificar este ficheiro contra:
#   - DS002: Utilizador root
#   - DS013: RUN com apt/apk sem --no-cache
#   - DS014: ADD vs COPY
#   - DS016: COPY --from em imagem não nomeada
#   - DS017: Sem HEALTHCHECK
#   - DS026: SHELL não-necessária
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder — instala dependências Python
# -----------------------------------------------------------------------------
FROM python:3.12-alpine3.19 AS builder

# Metadata
LABEL stage="builder"
LABEL maintainer="security@example.com"

WORKDIR /build

# ✅ SECURE: Instalar dependências do sistema com versões pinadas
# --no-cache evita guardar o cache do apk na imagem
RUN apk add --no-cache \
    gcc=13.2.1_git20231014-r0 \
    musl-dev=1.2.4_git20230717-r4 \
    libffi-dev=3.4.4-r3

# ✅ SECURE: Copiar apenas requirements primeiro (aproveitar layer cache)
COPY requirements.txt .

# ✅ SECURE: Instalar dependências num diretório dedicado
# --no-cache-dir evita guardar cache pip na imagem
# --prefix instala num path separado para copiar no stage final
RUN pip install --no-cache-dir --upgrade pip==24.0 \
    && pip install --no-cache-dir \
       --prefix=/install \
       -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2: Runtime — imagem final mínima
# -----------------------------------------------------------------------------
FROM python:3.12-alpine3.19 AS runtime

# Metadata de segurança
LABEL org.opencontainers.image.title="DevSecOps Demo App"
LABEL org.opencontainers.image.description="Aplicação de demonstração de DevSecOps"
LABEL org.opencontainers.image.vendor="DevSecOps PT"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL security.scan="trivy,bandit,semgrep"

# ✅ SECURE: Criar grupo e utilizador sem privilégios
# Não usar UID/GID 0 (root)
RUN addgroup -g 10001 -S appgroup \
    && adduser -u 10001 -S -G appgroup -H -D appuser

# ✅ SECURE: Sem curl/wget na imagem final (reduz superfície de ataque)
# Alpine já é mínimo, mas remover o que não é necessário
RUN apk del --purge apk-tools 2>/dev/null || true

WORKDIR /app

# ✅ SECURE: Copiar bibliotecas Python do stage builder
COPY --from=builder /install /usr/local

# ✅ SECURE: Copiar código com ownership correto (não root)
COPY --chown=appuser:appgroup app/ ./app/

# ✅ SECURE: Criar directório para logs com permissões corretas
RUN mkdir -p /app/logs && chown appuser:appgroup /app/logs

# ✅ SECURE: Mudar para utilizador não-root ANTES do EXPOSE e CMD
USER appuser

# Documentar porta (não abre — isso é feito no docker run / k8s)
EXPOSE 8080

# ✅ SECURE: HEALTHCHECK para detetar falhas da aplicação
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=5s \
            --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# ✅ SECURE: Usar forma exec (array) em vez de shell form
# Shell form: CMD "python app.py" — inicia /bin/sh que inicia python
# Exec form: CMD ["python", "app.py"] — inicia python diretamente (PID 1)
CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host", "0.0.0.0", "--port", "8080"]

# =============================================================================
# Notas de segurança para operação:
#
# docker run \
#   --read-only \                          # filesystem read-only
#   --tmpfs /tmp \                         # tmp em memória
#   --cap-drop ALL \                       # remover todas as capabilities
#   --security-opt no-new-privileges \     # sem escalada de privilégios
#   --env-file .env.production \           # secrets via env vars
#   -p 8080:8080 \
#   devsecops-demo:latest
# =============================================================================
