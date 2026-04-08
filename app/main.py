"""
DevSecOps Demo Application — Flask
====================================
Este ficheiro demonstra vulnerabilidades comuns e as suas correções.
Cada secção está documentada com o tipo de vulnerabilidade, o CVE associado
e a forma correta de mitigar.

NOTA: As funções marcadas com [INSECURE - DEMO ONLY] existem apenas para
demonstrar o que o Bandit/Semgrep irão detetar. NÃO usar em produção.
"""

import os
import logging
import hashlib
import secrets
from flask import Flask, request, jsonify


from app.secure.auth import require_api_key, generate_token
from app.secure.validation import validate_user_input, sanitize_filename

# ---------------------------------------------------------------------------
# Configuração segura da aplicação
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ✅ SECURE: Secret key carregada de variável de ambiente, nunca hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY não está definida. "
        "Defina a variável de ambiente antes de iniciar a aplicação."
    )

# ✅ SECURE: Logging estruturado sem dados sensíveis
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Health check (sem autenticação — endpoint público)
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Endpoint de health check para load balancers e probes."""
    return jsonify({"status": "ok", "version": "1.0.0"})


# ---------------------------------------------------------------------------
# DEMO: SQL Injection
# ---------------------------------------------------------------------------

# ❌ INSECURE — demonstração para Bandit/Semgrep (nunca usar em produção)
def _demo_insecure_query(username: str):
    """
    CWE-89 — SQL Injection
    CVSS: 9.8 CRITICAL
    Bandit rule: B608 (hardcoded_sql_expressions)

    O input do utilizador é concatenado diretamente na query SQL,
    permitindo que um atacante injete código arbitrário.
    Exemplo de payload malicioso: ' OR '1'='1
    """
    # fmt: off
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # noqa: S608
    # fmt: on
    logger.warning("DEMO ONLY — query insegura gerada: %s", query)
    return query


# ✅ SECURE — query parametrizada
def _demo_secure_query(username: str) -> str:
    """
    Correção: usar queries parametrizadas / prepared statements.
    O driver da base de dados trata o escape automaticamente.
    """
    # Com SQLAlchemy / psycopg2:
    # cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # Com SQLite:
    # cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return "SELECT * FROM users WHERE username = ?"


@app.route("/demo/sqli")
@require_api_key
def demo_sql_injection():
    """Demonstra SQL injection vs. query parametrizada."""
    username = request.args.get("username", "guest")
    insecure = _demo_insecure_query(username)
    secure = _demo_secure_query(username)
    return jsonify({
        "vulnerability": "SQL Injection (CWE-89)",
        "cvss": "9.8 CRITICAL",
        "insecure_query": insecure,
        "secure_query": secure,
        "fix": "Usar queries parametrizadas / ORM com escape automático",
    })


# ---------------------------------------------------------------------------
# DEMO: Hardcoded Secrets
# ---------------------------------------------------------------------------

# ❌ INSECURE — Bandit B105/B106/B107 deteta isto
_DEMO_HARDCODED_PASSWORD = "super_secret_123"  # noqa: S105
_DEMO_HARDCODED_API_KEY = "sk-prod-abc123xyz"   # noqa: S105


# ✅ SECURE — carregar de variável de ambiente ou secrets manager
def _get_db_password() -> str:
    """Carrega a password da base de dados de forma segura."""
    password = os.environ.get("DB_PASSWORD")
    if not password:
        raise RuntimeError("DB_PASSWORD não está configurada")
    return password


@app.route("/demo/secrets")
@require_api_key
def demo_hardcoded_secrets():
    """Demonstra hardcoded secrets vs. carregamento seguro."""
    return jsonify({
        "vulnerability": "Hardcoded Credentials (CWE-798)",
        "cvss": "7.5 HIGH",
        "insecure_examples": [
            "password = 'super_secret_123'",
            "api_key = 'sk-prod-abc123xyz'",
            "JWT_SECRET = 'changeme'",
        ],
        "secure_alternatives": [
            "os.environ.get('DB_PASSWORD')",
            "HashiCorp Vault: client.secrets.kv.read_secret('myapp/db')",
            "AWS Secrets Manager: boto3 get_secret_value()",
            "Azure Key Vault: SecretClient.get_secret()",
        ],
        "bandit_rules": ["B105", "B106", "B107"],
    })


# ---------------------------------------------------------------------------
# DEMO: Command Injection
# ---------------------------------------------------------------------------

# ❌ INSECURE — Bandit B605/B607
def _demo_insecure_ping(host: str) -> str:
    """
    CWE-78 — OS Command Injection
    CVSS: 9.8 CRITICAL
    Payload malicioso: 8.8.8.8; rm -rf /
    """
    import subprocess  # noqa: PLC0415
    # NUNCA fazer isto:
    cmd = f"ping -c 1 {host}"  # noqa
    logger.warning("DEMO ONLY — comando inseguro: %s", cmd)
    return cmd


# ✅ SECURE — lista de argumentos, sem shell=True
def _demo_secure_ping(host: str) -> dict:
    """
    Correção:
    1. Validar o host contra uma allowlist/regex
    2. Passar argumentos como lista (nunca string interpolada)
    3. Nunca usar shell=True com input do utilizador
    """
    import re
    import subprocess  # noqa: PLC0415

    # Validar que é um IP ou hostname válido
    if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", host):
        return {"error": "Host inválido"}

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],  # lista de args — seguro
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            # shell=False é o default — NUNCA usar shell=True com user input
        )
        return {"returncode": result.returncode, "output": result.stdout[:200]}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}


@app.route("/demo/cmdi")
@require_api_key
def demo_command_injection():
    """Demonstra command injection vs. execução segura de subprocessos."""
    host = request.args.get("host", "127.0.0.1")
    insecure_cmd = _demo_insecure_ping(host)
    secure_result = _demo_secure_ping(host)
    return jsonify({
        "vulnerability": "OS Command Injection (CWE-78)",
        "cvss": "9.8 CRITICAL",
        "insecure_command": insecure_cmd,
        "secure_result": secure_result,
        "fix": "Usar lista de args em subprocess.run(), validar input, nunca shell=True",
        "bandit_rules": ["B603", "B605", "B607"],
    })


# ---------------------------------------------------------------------------
# DEMO: Insecure Deserialization
# ---------------------------------------------------------------------------

@app.route("/demo/deserialization", methods=["POST"])
@require_api_key
def demo_deserialization():
    """
    CWE-502 — Deserialization of Untrusted Data
    Bandit B301/B302 (pickle usage)
    """
    return jsonify({
        "vulnerability": "Insecure Deserialization (CWE-502)",
        "cvss": "9.8 CRITICAL",
        "insecure": "pickle.loads(user_data)  # NUNCA deserializar input não confiável",
        "secure_alternatives": [
            "JSON: json.loads() — apenas tipos primitivos, seguro",
            "marshmallow — validação + deserialização com schema",
            "pydantic — type-safe parsing com validação",
        ],
        "bandit_rules": ["B301", "B302", "B303"],
    })


# ---------------------------------------------------------------------------
# DEMO: Weak Cryptography
# ---------------------------------------------------------------------------

# ❌ INSECURE — MD5/SHA1 para passwords (Bandit B303/B324)
def _demo_insecure_hash(password: str) -> str:  # nosec B303 B324
    """MD5 é quebrado para passwords — não usar."""
    return hashlib.md5(password.encode()).hexdigest()  # nosec B324


# ✅ SECURE — bcrypt / argon2 com salt
def _demo_secure_hash(password: str) -> dict:
    """
    Para passwords: usar bcrypt, argon2, ou scrypt.
    Para checksums não-criptográficos: SHA-256 é aceitável.
    """
    # Exemplo com hashlib.scrypt (built-in, seguro para passwords)
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,  # CPU/memory cost
        r=8,
        p=1,
        dklen=32,
    )
    return {
        "algorithm": "scrypt",
        "salt": salt.hex(),
        "hash": key.hex(),
    }


@app.route("/demo/crypto")
@require_api_key
def demo_weak_crypto():
    """Demonstra criptografia fraca vs. algoritmos seguros."""
    test_password = "example_password_for_demo"
    return jsonify({
        "vulnerability": "Weak Cryptography (CWE-327, CWE-328)",
        "insecure": {
            "algorithm": "MD5",
            "cvss": "7.5 HIGH",
            "hash": _demo_insecure_hash(test_password),
            "why_insecure": "MD5 tem colisões conhecidas, sem salt, GPU crackable",
        },
        "secure": {
            "algorithm": "scrypt",
            **_demo_secure_hash(test_password),
            "why_secure": "Key derivation function, salt único, memory-hard",
        },
        "bandit_rules": ["B303", "B324"],
    })


# ---------------------------------------------------------------------------
# DEMO: Path Traversal
# ---------------------------------------------------------------------------

# ❌ INSECURE — CWE-22
def _demo_insecure_read(filename: str) -> str:
    """Payload malicioso: ../../../../etc/passwd"""
    base_dir = "/app/uploads"
    filepath = os.path.join(base_dir, filename)
    logger.warning("DEMO ONLY — path inseguro: %s", filepath)
    return filepath


# ✅ SECURE — usar sanitize_filename do módulo secure
def _demo_secure_read(filename: str) -> str:
    """Correção: usar secure.validation.sanitize_filename()"""
    safe_name = sanitize_filename(filename)
    base_dir = "/app/uploads"
    filepath = os.path.realpath(os.path.join(base_dir, safe_name))
    # Garantir que o path resultante está dentro da base_dir
    if not filepath.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal detetado")
    return filepath


@app.route("/demo/path-traversal")
@require_api_key
def demo_path_traversal():
    """Demonstra path traversal vs. validação de path segura."""
    filename = request.args.get("file", "report.pdf")
    insecure_path = _demo_insecure_read(filename)
    try:
        secure_path = _demo_secure_read(filename)
    except ValueError as e:
        secure_path = f"BLOQUEADO: {e}"
    return jsonify({
        "vulnerability": "Path Traversal (CWE-22)",
        "cvss": "7.5 HIGH",
        "input": filename,
        "insecure_path": insecure_path,
        "secure_path": secure_path,
        "fix": "os.path.realpath() + verificar que path começa na base_dir",
        "bandit_rules": ["B101"],
    })


# ---------------------------------------------------------------------------
# Endpoint de sumário — Security Dashboard
# ---------------------------------------------------------------------------

@app.route("/security/summary")
@require_api_key
def security_summary():
    """Sumário de todas as vulnerabilidades demonstradas nesta aplicação."""
    return jsonify({
        "application": "DevSecOps Demo",
        "version": "1.0.0",
        "vulnerabilities_demonstrated": [
            {
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "cvss": "9.8 CRITICAL",
                "endpoint": "/demo/sqli",
                "tool": "Bandit B608, Semgrep",
                "status": "mitigated",
            },
            {
                "cwe": "CWE-798",
                "name": "Hardcoded Credentials",
                "cvss": "7.5 HIGH",
                "endpoint": "/demo/secrets",
                "tool": "Bandit B105/B106/B107, Semgrep",
                "status": "mitigated",
            },
            {
                "cwe": "CWE-78",
                "name": "OS Command Injection",
                "cvss": "9.8 CRITICAL",
                "endpoint": "/demo/cmdi",
                "tool": "Bandit B603/B605/B607",
                "status": "mitigated",
            },
            {
                "cwe": "CWE-502",
                "name": "Insecure Deserialization",
                "cvss": "9.8 CRITICAL",
                "endpoint": "/demo/deserialization",
                "tool": "Bandit B301/B302",
                "status": "mitigated",
            },
            {
                "cwe": "CWE-327",
                "name": "Weak Cryptography",
                "cvss": "7.5 HIGH",
                "endpoint": "/demo/crypto",
                "tool": "Bandit B303/B324",
                "status": "mitigated",
            },
            {
                "cwe": "CWE-22",
                "name": "Path Traversal",
                "cvss": "7.5 HIGH",
                "endpoint": "/demo/path-traversal",
                "tool": "Bandit B101, Semgrep",
                "status": "mitigated",
            },
        ],
        "pipeline_stages": [
            "SAST — Bandit + Semgrep",
            "SCA — pip-audit + OWASP Dependency Check",
            "Container Scan — Trivy",
            "IaC Scan — Trivy Dockerfile",
            "SARIF → GitHub Security Tab",
        ],
    })


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "detail": str(e)}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found"}), 404


@app.errorhandler(500)
def internal_error(e):
    # ✅ SECURE: nunca expor stack traces ao cliente
    logger.exception("Internal server error")
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == "__main__":
    # ✅ SECURE: debug=False em produção, lido de variável de ambiente
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)  # nosec B104
