"""
app/secure/auth.py
==================
Módulo de autenticação segura.

Implementa:
- API key validation com comparação em tempo constante (contra timing attacks)
- JWT token generation com claims seguros
- Rate limiting decorator (estrutura — implementar com Redis em produção)
"""

import os
import time
import hmac
import hashlib
import secrets
import logging
from functools import wraps
from typing import Optional
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes de segurança
# ---------------------------------------------------------------------------

TOKEN_EXPIRY_SECONDS = 3600          # 1 hora
MIN_API_KEY_LENGTH = 32              # mínimo 256 bits de entropia
RATE_LIMIT_REQUESTS = 100            # requests por janela
RATE_LIMIT_WINDOW_SECONDS = 60       # janela de 60 segundos


# ---------------------------------------------------------------------------
# API Key Validation
# ---------------------------------------------------------------------------

def _get_expected_api_key() -> str:
    """
    Carrega a API key esperada de variável de ambiente.
    Nunca hardcoded — CWE-798.
    """
    key = os.environ.get("API_KEY")
    if not key:
        raise RuntimeError(
            "API_KEY não está definida. "
            "Configure a variável de ambiente antes de iniciar."
        )
    if len(key) < MIN_API_KEY_LENGTH:
        raise RuntimeError(
            f"API_KEY demasiado curta. Mínimo {MIN_API_KEY_LENGTH} caracteres."
        )
    return key


def _constant_time_compare(val1: str, val2: str) -> bool:
    """
    Comparação em tempo constante para evitar timing attacks (CWE-208).

    hmac.compare_digest() garante que o tempo de comparação é sempre
    o mesmo, independentemente de onde ocorre a primeira diferença.
    Sem isto, um atacante pode inferir o valor correto medindo o tempo
    de resposta.
    """
    return hmac.compare_digest(
        val1.encode("utf-8"),
        val2.encode("utf-8"),
    )


def validate_api_key(provided_key: Optional[str]) -> bool:
    """Valida a API key de forma segura."""
    if not provided_key:
        return False
    try:
        expected = _get_expected_api_key()
    except RuntimeError:
        logger.error("API_KEY não configurada no ambiente")
        return False
    return _constant_time_compare(provided_key, expected)


def require_api_key(f):
    """
    Decorator que exige API key válida no header Authorization.

    Uso:
        @app.route("/protected")
        @require_api_key
        def protected_endpoint():
            ...

    Header esperado:
        Authorization: Bearer <api_key>
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        # Suportar "Bearer <key>" e "<key>" direto
        if auth_header.startswith("Bearer "):
            provided_key = auth_header[7:]
        else:
            provided_key = auth_header

        if not validate_api_key(provided_key):
            logger.warning(
                "Acesso negado a %s — API key inválida ou ausente. IP: %s",
                request.path,
                request.remote_addr,
            )
            # ✅ SECURE: não revelar se a key existe mas está errada
            return jsonify({"error": "Unauthorized"}), 401

        # Logar acesso autenticado (sem logar a key!)
        logger.info(
            "Acesso autenticado a %s. IP: %s",
            request.path,
            request.remote_addr,
        )
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Token Generation (HMAC-based)
# ---------------------------------------------------------------------------

def generate_token(user_id: str, expiry_seconds: int = TOKEN_EXPIRY_SECONDS) -> dict:
    """
    Gera um token HMAC seguro com expiração.

    Em produção, usar PyJWT com algoritmo RS256 (chave assimétrica):
        import jwt
        token = jwt.encode(payload, private_key, algorithm="RS256")

    Esta implementação usa HMAC-SHA256 como exemplo educacional.
    """
    # ✅ SECURE: token com 32 bytes de entropia (256 bits)
    token_id = secrets.token_urlsafe(32)
    issued_at = int(time.time())
    expires_at = issued_at + expiry_seconds

    # Payload que será assinado
    payload = f"{token_id}:{user_id}:{issued_at}:{expires_at}"

    # ✅ SECURE: assinar com HMAC-SHA256
    secret = os.environ.get("TOKEN_SECRET", "").encode()
    if not secret:
        raise RuntimeError("TOKEN_SECRET não está configurado")

    signature = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

    return {
        "token": f"{payload}:{signature}",
        "token_id": token_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "token_type": "Bearer",
    }


def verify_token(token: str) -> Optional[dict]:
    """
    Verifica e valida um token HMAC.
    Retorna o payload ou None se inválido/expirado.
    """
    try:
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return None

        payload, provided_sig = parts

        # Re-calcular a assinatura esperada
        secret = os.environ.get("TOKEN_SECRET", "").encode()
        expected_sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

        # ✅ SECURE: comparação em tempo constante
        if not hmac.compare_digest(provided_sig, expected_sig):
            logger.warning("Token com assinatura inválida")
            return None

        # Verificar expiração
        token_parts = payload.split(":")
        if len(token_parts) != 4:
            return None

        token_id, user_id, issued_at, expires_at = token_parts
        if int(time.time()) > int(expires_at):
            logger.info("Token expirado para user_id=%s", user_id)
            return None

        return {
            "token_id": token_id,
            "user_id": user_id,
            "issued_at": int(issued_at),
            "expires_at": int(expires_at),
        }

    except (ValueError, AttributeError) as e:
        logger.warning("Erro ao verificar token: %s", e)
        return None
