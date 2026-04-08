"""
app/secure/validation.py
=========================
Módulo de validação e sanitização de inputs.

Implementa:
- Validação de tipos e formatos com regex allowlist
- Sanitização de nomes de ficheiro (path traversal prevention)
- Validação de URLs (SSRF prevention)
- Input length limiting
- Schema validation com pydantic
"""

import re
import os
import logging
import ipaddress
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes de validação
# ---------------------------------------------------------------------------

MAX_STRING_LENGTH = 1000
MAX_FILENAME_LENGTH = 255
MAX_URL_LENGTH = 2048

# Allowlist de caracteres válidos para nomes de ficheiro
# ✅ SECURE: allowlist em vez de blocklist (CWE-184)
SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,255}$")

# Padrão de username válido
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")

# Padrão de email válido (simplificado — usar email-validator em produção)
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Domínios internos bloqueados para prevenir SSRF
BLOCKED_HOSTS = {
    "localhost",
    "0.0.0.0",
    "metadata.google.internal",  # GCP metadata
    "169.254.169.254",           # AWS/Azure metadata
    "100.100.100.200",           # Alibaba Cloud metadata
}

# Redes privadas bloqueadas para SSRF prevention
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
]


# ---------------------------------------------------------------------------
# Validação de Input Genérico
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Excepção para erros de validação de input."""
    pass


def validate_user_input(
    value: Any,
    field_name: str,
    max_length: int = MAX_STRING_LENGTH,
    required: bool = True,
) -> str:
    """
    Valida e sanitiza input de utilizador genérico.

    Args:
        value: Valor a validar
        field_name: Nome do campo (para mensagens de erro)
        max_length: Comprimento máximo permitido
        required: Se True, rejeita valores vazios

    Returns:
        String sanitizada

    Raises:
        ValidationError: Se o valor não passar na validação
    """
    # Verificar None/vazio
    if value is None or value == "":
        if required:
            raise ValidationError(f"Campo '{field_name}' é obrigatório")
        return ""

    # Converter para string
    if not isinstance(value, str):
        value = str(value)

    # ✅ SECURE: limitar comprimento antes de qualquer processamento
    if len(value) > max_length:
        raise ValidationError(
            f"Campo '{field_name}' excede o comprimento máximo de {max_length} caracteres"
        )

    # ✅ SECURE: strip de whitespace
    value = value.strip()

    # ✅ SECURE: remover null bytes (CWE-158)
    if "\x00" in value:
        raise ValidationError(f"Campo '{field_name}' contém caracteres inválidos")

    return value


def validate_username(username: str) -> str:
    """
    Valida username contra allowlist de padrão.

    Previne: SQL injection, XSS, path traversal no username.
    """
    username = validate_user_input(username, "username", max_length=64)

    if not USERNAME_PATTERN.match(username):
        raise ValidationError(
            "Username inválido. Apenas letras, números, _, - e . são permitidos. "
            "Mínimo 3, máximo 64 caracteres."
        )

    return username


def validate_email(email: str) -> str:
    """Valida formato de email."""
    email = validate_user_input(email, "email", max_length=254)
    email = email.lower()

    if not EMAIL_PATTERN.match(email):
        raise ValidationError("Email inválido")

    return email


# ---------------------------------------------------------------------------
# Sanitização de Nomes de Ficheiro — Path Traversal Prevention (CWE-22)
# ---------------------------------------------------------------------------

def sanitize_filename(filename: str) -> str:
    """
    Sanitiza nome de ficheiro para prevenir path traversal (CWE-22).

    Estratégia: allowlist de caracteres seguros.
    Rejeita qualquer input com separadores de path, null bytes,
    ou caracteres nao-alfanumericos exceto _, -, .

    Exemplos de ataques bloqueados:
        ../../../etc/passwd      -> erro (contém /)
        ....//....//etc/passwd   -> erro (contém /)
        file\\x00.pdf            -> erro (null byte)
        /absolute/path/file.pdf  -> erro (contém /)

    Args:
        filename: Nome de ficheiro fornecido pelo utilizador

    Returns:
        Nome de ficheiro sanitizado e seguro

    Raises:
        ValidationError: Se o nome nao puder ser sanitizado
    """
    if not filename:
        raise ValidationError("Nome de ficheiro não pode estar vazio")

    # Limitar comprimento
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValidationError(
            f"Nome de ficheiro demasiado longo. Máximo {MAX_FILENAME_LENGTH} caracteres."
        )

    # ✅ SECURE: Rejeitar ANTES de qualquer transformação — bloquear separadores de path
    # Nota: os.path.basename() pode ser contornado em edge cases — rejeitar diretamente
    if "/" in filename or "\\" in filename:
        raise ValidationError("Nome de ficheiro não pode conter separadores de path")

    # Rejeitar null bytes (CWE-158)
    if "\x00" in filename:
        raise ValidationError("Nome de ficheiro contém caracteres inválidos")

    # Rejeitar sequências de path traversal (.. e variantes)
    if ".." in filename:
        raise ValidationError("Nome de ficheiro contém sequência de path traversal")

    # Verificar contra allowlist de padrão (apenas alfanumérico + _, -, .)
    if not SAFE_FILENAME_PATTERN.match(filename):
        raise ValidationError(
            "Nome de ficheiro contém caracteres inválidos. "
            "Apenas letras, números, _, -, . são permitidos."
        )

    # Rejeitar nomes que começam com ponto (ficheiros ocultos como .env, .htaccess)
    if filename.startswith("."):
        raise ValidationError("Nome de ficheiro não pode começar com '.'")

    return filename


def safe_join(base_dir: str, filename: str) -> str:
    """
    Junta um diretório base com um filename de forma segura.

    Garante que o path resultante está dentro do base_dir.
    Equivalente ao werkzeug.security.safe_join().

    Args:
        base_dir: Diretório base (absoluto)
        filename: Nome de ficheiro sanitizado

    Returns:
        Path absoluto seguro

    Raises:
        ValidationError: Se o path resultante sair do base_dir
    """
    # Sanitizar o filename primeiro
    safe_name = sanitize_filename(filename)

    # Construir path e resolver symlinks/..
    full_path = os.path.realpath(os.path.join(base_dir, safe_name))
    real_base = os.path.realpath(base_dir)

    # ✅ SECURE: verificar que o path resultante está dentro da base
    if not full_path.startswith(real_base + os.sep) and full_path != real_base:
        logger.warning(
            "Path traversal detetado: base=%s, filename=%s, resolved=%s",
            real_base,
            filename,
            full_path,
        )
        raise ValidationError("Acesso negado: path fora do diretório permitido")

    return full_path


# ---------------------------------------------------------------------------
# SSRF Prevention — URL Validation (CWE-918)
# ---------------------------------------------------------------------------

def validate_url(url: str, allowed_schemes: Optional[list] = None) -> str:
    """
    Valida URL para prevenir SSRF (Server-Side Request Forgery, CWE-918).

    Bloqueia:
    - Endereços de metadata cloud (169.254.169.254, etc.)
    - Redes privadas (10.x, 172.16.x, 192.168.x)
    - Schemas não permitidos (file://, ftp://, gopher://)
    - Localhost e loopback

    Args:
        url: URL a validar
        allowed_schemes: Lista de schemas permitidos (default: ["https"])

    Returns:
        URL validada

    Raises:
        ValidationError: Se a URL não for segura
    """
    if allowed_schemes is None:
        allowed_schemes = ["https"]  # ✅ Apenas HTTPS por default

    if not url:
        raise ValidationError("URL não pode estar vazia")

    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"URL demasiado longa. Máximo {MAX_URL_LENGTH} caracteres.")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"URL inválida: {e}") from e

    # Verificar schema
    if parsed.scheme not in allowed_schemes:
        raise ValidationError(
            f"Schema '{parsed.scheme}' não permitido. "
            f"Schemas permitidos: {allowed_schemes}"
        )

    # Extrair host
    host = parsed.hostname
    if not host:
        raise ValidationError("URL sem host válido")

    # Verificar hosts bloqueados
    if host.lower() in BLOCKED_HOSTS:
        logger.warning("SSRF tentativa bloqueada: host=%s", host)
        raise ValidationError(f"Host '{host}' não é permitido")

    # Verificar se é endereço IP privado
    try:
        ip = ipaddress.ip_address(host)
        for network in PRIVATE_NETWORKS:
            if ip in network:
                logger.warning(
                    "SSRF tentativa bloqueada: IP privado=%s", host
                )
                raise ValidationError(
                    "Endereços IP privados não são permitidos"
                )
    except ValueError:
        # Não é um IP — é um hostname, verificar se resolve para IP privado
        # Em produção, fazer DNS lookup e verificar o IP resultante
        pass

    return url
