# 🔐 DevSecOps Pipeline — Shift Left Security

[![Security Pipeline](https://github.com/devcarlosfigueiredo/devsecops-pipeline/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/devcarlosfigueiredo/devsecops-pipeline/actions/workflows/security-pipeline.yml)
[![Dependency Scan](https://github.com/devcarlosfigueiredo/devsecops-pipeline/actions/workflows/dependency-scan.yml/badge.svg)](https://github.com/devcarlosfigueiredo/devsecops-pipeline/actions/workflows/dependency-scan.yml)
[![Security Rating](https://img.shields.io/badge/Security-A%2B-brightgreen)](SECURITY.md)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Covered-blue)](SECURITY.md#owasp-top-10-2021)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Demonstração completa de DevSecOps com segurança integrada em **cada fase** do pipeline CI/CD.
> Philosophy **"Shift Left"**: vulnerabilidades são detetadas e bloqueadas antes de chegarem a produção.

---

## 🎯 O Que Este Projeto Demonstra

| Competência | Ferramenta | Valor para Empregador |
|-------------|------------|----------------------|
| **SAST** — análise estática de código | Bandit + Semgrep | Detetar bugs de segurança antes do code review |
| **SCA** — dependências vulneráveis | pip-audit | Zero CVEs conhecidos em produção |
| **Container Security** | Trivy | Imagens hardened, não-root, superfície mínima |
| **IaC Security** | Trivy Config | Dockerfile e infra seguros por design |
| **Shift Left** | GitHub Actions | Segurança no PR, não no pentest anual |
| **SARIF Integration** | GitHub Security Tab | Visibilidade centralizada de vulnerabilidades |
| **NIS2 Alignment** | Pipeline + SECURITY.md | Conformidade europeia com evidências auditáveis |

---

## 🏗️ Arquitetura do Pipeline

```
Push / Pull Request
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  Stage 1: SAST — Static Application Security Testing  │
│  ┌─────────────────┐   ┌──────────────────────────┐   │
│  │ Bandit          │   │ Semgrep                  │   │
│  │ • B105 hardcode │   │ • OWASP Top 10           │   │
│  │ • B608 SQL inj  │   │ • p/python, p/flask      │   │
│  │ • B301 pickle   │   │ • Regras customizadas    │   │
│  │ ❌ Falha: HIGH  │   │ ❌ Falha: ERROR severity │   │
│  └─────────────────┘   └──────────────────────────┘   │
└───────────────────────────────────────────────────────┘
        │ (apenas se SAST passou)
        ▼
┌───────────────────────────────────────────────────────┐
│  Stage 2: SCA — Software Composition Analysis         │
│  ┌─────────────────────────────────────────────────┐  │
│  │ pip-audit                                       │  │
│  │ • Verifica CVEs em requirements.txt             │  │
│  │ • CVSS score por vulnerabilidade                │  │
│  │ • Gera SBOM (CycloneDX JSON)                   │  │
│  │ ❌ Falha: qualquer CVE com fix disponível       │  │
│  └─────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────┘
        │ (apenas se SCA passou)
        ▼
┌───────────────────────────────────────────────────────┐
│  Stage 3: Build Docker                                │
│  • Multi-stage build (Alpine, non-root)               │
│  • Layer cache optimizado                             │
│  • Imagem exportada para stages seguintes             │
└───────────────────────────────────────────────────────┘
        │
        ├─────────────────────────────────────┐
        ▼                                     ▼
┌──────────────────────┐         ┌────────────────────────┐
│ Stage 4: Container   │         │ Stage 5: IaC Scan      │
│ Scan — Trivy         │         │ Trivy Config           │
│ • CVEs em OS pkgs    │         │ • Dockerfile checks    │
│ • CVEs em libraries  │         │ • DS002: root user     │
│ ❌ Falha: CRITICAL   │         │ • DS017: healthcheck   │
└──────────────────────┘         │ ❌ Falha: HIGH         │
        │                        └────────────────────────┘
        └─────────────────────────────────────┘
        │ (ambos passaram)
        ▼
┌───────────────────────────────────────────────────────┐
│  Stage 6: Publicar SARIF → GitHub Security Tab        │
│  • Bandit results                                     │
│  • Semgrep results                                    │
│  • Trivy container results                            │
│  • Trivy IaC results                                  │
└───────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  Stage 7: Security Report Consolidado                 │
│  • JSON com todos os resultados                       │
│  • Comentário automático no PR                        │
│  • Artefacto retido 90 dias                           │
└───────────────────────────────────────────────────────┘
        │ (apenas em main + todos stages OK)
        ▼
┌───────────────────────────────────────────────────────┐
│  Deploy — Produção                                    │
│  Apenas executado se TODOS os stages anteriores       │
│  passaram. Zero-tolerance para CRITICAL.              │
└───────────────────────────────────────────────────────┘
```

---

## 🚀 Setup Rápido

### Pré-requisitos

```bash
python >= 3.12
docker >= 24.0
```

### 1. Clonar e instalar

```bash
git clone https://github.com/devcarlosfigueiredo/devsecops-pipeline.git
cd devsecops-pipeline

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements-dev.txt
```

### 2. Configurar variáveis de ambiente

```bash
# Copiar template
cp .env.example .env

# Editar com valores reais (NUNCA commitar o .env)
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export TOKEN_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

### 3. Executar testes de segurança localmente

```bash
# Testes da aplicação
pytest tests/ -v --tb=short

# SAST com Bandit
bandit --recursive app/ --configfile .bandit --severity-level HIGH

# SCA com pip-audit
pip-audit --requirement requirements.txt

# Container scan (após build)
docker build -t devsecops-pipeline:local .
trivy image --severity CRITICAL,HIGH devsecops-pipeline:local

# IaC scan
trivy config --severity HIGH,CRITICAL .
```

### 4. Iniciar a aplicação

```bash
# Desenvolvimento
FLASK_DEBUG=true flask --app app.main run --port 8080

# Produção (Docker)
docker run \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -e FLASK_SECRET_KEY="$FLASK_SECRET_KEY" \
  -e API_KEY="$API_KEY" \
  -p 8080:8080 \
  devsecops-pipeline:local
```

---

## 📂 Estrutura do Projeto

```
devsecops-pipeline/
├── app/
│   ├── main.py                  # Flask app com demos de vulnerabilidades
│   └── secure/
│       ├── auth.py              # Autenticação segura (HMAC, timing-safe)
│       └── validation.py        # Validação de inputs (path traversal, SSRF)
├── tests/
│   └── test_security.py         # Testes de segurança automatizados
├── .github/
│   └── workflows/
│       ├── security-pipeline.yml   # Pipeline principal
│       └── dependency-scan.yml     # Scan agendado de dependências
├── Dockerfile                   # Multi-stage, non-root, hardened
├── requirements.txt             # Dependências com versões pinadas
├── requirements-dev.txt         # Dependências de desenvolvimento
├── .bandit                      # Configuração Bandit (SAST)
├── .semgrep.yml                 # Regras customizadas Semgrep
├── .trivyignore                 # CVEs ignorados (com justificação)
├── SECURITY.md                  # Política de disclosure e segurança
└── README.md                    # Este ficheiro
```

---

## 🔍 Vulnerabilidades Demonstradas

A aplicação inclui exemplos documentados de vulnerabilidades e as suas correções:

| Endpoint | CWE | Vulnerabilidade | CVSS | Tool que Deteta |
|----------|-----|-----------------|------|-----------------|
| `/demo/sqli` | CWE-89 | SQL Injection | 9.8 CRITICAL | Bandit B608, Semgrep |
| `/demo/secrets` | CWE-798 | Hardcoded Credentials | 7.5 HIGH | Bandit B105-B107 |
| `/demo/cmdi` | CWE-78 | OS Command Injection | 9.8 CRITICAL | Bandit B603/B607 |
| `/demo/deserialization` | CWE-502 | Insecure Deserialization | 9.8 CRITICAL | Bandit B301/B302 |
| `/demo/crypto` | CWE-327/328 | Weak Cryptography (MD5) | 7.5 HIGH | Bandit B303/B324 |
| `/demo/path-traversal` | CWE-22 | Path Traversal | 7.5 HIGH | Bandit B101, Semgrep |

> **Nota:** As implementações inseguras existem apenas para demonstração do pipeline.
> O código de produção usa sempre as alternativas seguras documentadas.

### Testar os endpoints

```bash
API_KEY="your-api-key-here"

# Ver sumário de todas as vulnerabilidades
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/security/summary

# Demo SQL Injection
curl -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8080/demo/sqli?username=alice"

# Demo Path Traversal (tentativa maliciosa bloqueada)
curl -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8080/demo/path-traversal?file=../../../etc/passwd"
```

---

## 🛡️ Boas Práticas Implementadas

### Código
- ✅ Zero hardcoded secrets — todos carregados de variáveis de ambiente
- ✅ Comparações em tempo constante (`hmac.compare_digest`) — anti timing-attack
- ✅ Queries parametrizadas — zero SQL injection
- ✅ Allowlist de caracteres em validação de input (não blocklist)
- ✅ Path traversal prevention com `os.path.realpath()` + verificação de prefix
- ✅ SSRF prevention com blocklist de IPs/hosts internos
- ✅ Criptografia forte (scrypt para passwords, nunca MD5/SHA1)
- ✅ Logging sem dados sensíveis

### Container
- ✅ `python:3.12-alpine3.19` — imagem base mínima (< 50MB)
- ✅ Multi-stage build — sem ferramentas de build na imagem final
- ✅ `USER appuser` (UID 10001) — nunca root
- ✅ `--read-only` filesystem em runtime
- ✅ `--cap-drop ALL` — sem capabilities de sistema
- ✅ `HEALTHCHECK` configurado
- ✅ Versões pinadas de todas as dependências

### Pipeline
- ✅ Permissões mínimas em GitHub Actions (`permissions: contents: read`)
- ✅ Secrets em GitHub Secrets — zero em código
- ✅ SARIF publicado automaticamente no GitHub Security Tab
- ✅ Comentário automático em PRs com resultado do security scan
- ✅ Artefactos retidos 30-90 dias para auditoria
- ✅ Scan agendado diário para novas CVEs em dependências existentes
- ✅ Issue automático criado se scan diário encontrar CRITICAL

---

## 📊 Interpretação dos Resultados

### GitHub Security Tab

Após o pipeline executar, os resultados aparecem em:
`https://github.com/devcarlosfigueiredo/devsecops-pipeline/security/code-scanning`

Cada alerta inclui:
- Tipo de vulnerabilidade e CWE
- Linha de código afetada
- Severidade (CRITICAL/HIGH/MEDIUM/LOW)
- Link para documentação de mitigação

### Thresholds Configuráveis

Editar em `.github/workflows/security-pipeline.yml`:

```yaml
env:
  SAST_FAIL_SEVERITY: "HIGH"           # Bandit: falha em HIGH ou CRITICAL
  SCA_FAIL_CVSS: "7.0"                 # pip-audit: falha se CVSS >= 7.0
  CONTAINER_FAIL_SEVERITY: "CRITICAL"  # Trivy: falha em CRITICAL
  IAC_FAIL_SEVERITY: "HIGH"            # Trivy IaC: falha em HIGH
```

> Em ambientes de desenvolvimento, considerar `SAST_FAIL_SEVERITY: "CRITICAL"`
> para evitar bloquear durante desenvolvimento ativo.

---

## 🔧 GitHub Actions Secrets Necessários

| Secret | Descrição | Obrigatório |
|--------|-----------|-------------|
| `SEMGREP_APP_TOKEN` | Token da app Semgrep (para dashboard) | Opcional |
| `REGISTRY_TOKEN` | Token para push de imagem para registry | Para deploy |

---

## 📚 Referências e Aprendizagem

### Standards e Frameworks
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [NIST NVD — CVE Database](https://nvd.nist.gov/)
- [NIS2 Directive (EU 2022/2555)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555)

### Ferramentas
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [pip-audit](https://github.com/pypa/pip-audit)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

## 🤝 Contribuir

1. Fork o repositório
2. Criar branch: `git checkout -b feature/nova-regra-seguranca`
3. Executar testes localmente: `pytest tests/ -v`
4. Executar SAST local: `bandit --recursive app/`
5. Submeter PR — o pipeline executa automaticamente
6. **O PR só pode ser mergiado se todos os security checks passarem**

Ver [SECURITY.md](SECURITY.md) para reportar vulnerabilidades.

---

## 📄 Licença

MIT License — ver [LICENSE](LICENSE)

---

*Desenvolvido como demonstração de competências DevSecOps para o mercado português e europeu.*
*Especialmente relevante para vagas em fintech, healthtech e empresas com requisitos NIS2.*
