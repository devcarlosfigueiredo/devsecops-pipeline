# Security Policy

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 1.x     | ✅ Supported       | Versão atual — recebe patches de segurança |
| < 1.0   | ❌ Not supported   | End of life |

---

## Reporting a Vulnerability

**Por favor NÃO reporte vulnerabilidades de segurança através de GitHub Issues públicos.**

### Processo de Responsible Disclosure

Seguimos o standard de **Coordinated Vulnerability Disclosure (CVD)** da ENISA.

#### 1. Contacto Inicial (Privado)

Envie um email para: **security@example.com**

Incluir no relatório:
- Descrição da vulnerabilidade (tipo, localização no código)
- Passos para reproduzir (PoC ou descrição detalhada)
- Impacto potencial (dados expostos, sistemas afetados)
- Severidade estimada (CVSS v3.1 score se possível)
- A sua identificação (opcional — aceitamos relatórios anónimos)

**Encriptar com PGP:** [Chave pública](https://example.com/.well-known/security.txt)

#### 2. Acknowledgement

Confirmaremos a receção do relatório em **48 horas úteis**.

#### 3. Avaliação e Triagem

Dentro de **5 dias úteis**, iremos:
- Confirmar se a vulnerabilidade é válida
- Atribuir severidade (CVSS v3.1)
- Comunicar o plano de mitigação

#### 4. Resolução

| Severidade | SLA de Fix |
|------------|------------|
| CRITICAL (CVSS ≥ 9.0) | 7 dias |
| HIGH (CVSS 7.0–8.9) | 30 dias |
| MEDIUM (CVSS 4.0–6.9) | 90 dias |
| LOW (CVSS < 4.0) | 180 dias |

#### 5. Divulgação Coordenada

Após o fix estar disponível:
- Publicamos um Security Advisory no GitHub
- Atribuímos crédito ao investigador (salvo se preferir anonimato)
- Pedimos ao investigador para aguardar 90 dias antes de divulgação pública

---

## Security Pipeline

Este repositório implementa segurança em cada etapa do desenvolvimento:

### SAST (Static Application Security Testing)
- **Bandit** — analisa o código Python para vulnerabilidades comuns
- **Semgrep** — análise semântica com regras OWASP Top 10

### SCA (Software Composition Analysis)
- **pip-audit** — verifica CVEs em todas as dependências Python
- **Trivy** — scan de filesystem e dependências

### Container Security
- **Trivy** — scan da imagem Docker para CVEs em pacotes OS e bibliotecas
- **Imagem Alpine** — superfície de ataque mínima
- **Non-root user** — sem privilégios de root no container

### IaC Security
- **Trivy Config** — verifica o Dockerfile e configurações contra best practices

### Thresholds de Bloqueio
| Scan | Bloqueia em |
|------|-------------|
| SAST (Bandit/Semgrep) | HIGH, CRITICAL |
| SCA (pip-audit) | Qualquer CVE com fix disponível |
| Container (Trivy) | CRITICAL |
| IaC (Trivy Config) | HIGH, CRITICAL |

---

## Security Hardening

### Imagem Docker
- Base: `python:3.12-alpine3.19` (mínima)
- Utilizador: `appuser` (UID 10001, sem root)
- Multi-stage build (sem ferramentas de build na imagem final)
- `--read-only` filesystem em runtime
- `--cap-drop ALL` (sem capabilities de sistema)

### Aplicação
- Todos os secrets carregados de variáveis de ambiente
- Zero hardcoded credentials
- Queries parametrizadas (sem SQL injection)
- Input validation com allowlist
- Rate limiting nos endpoints de autenticação
- Logging sem dados sensíveis
- HMAC para comparações de segurança (anti-timing-attack)

### CI/CD
- Permissões mínimas nos GitHub Actions (principle of least privilege)
- Secrets apenas em GitHub Secrets (nunca em código)
- SARIF publicado no GitHub Security Tab em cada PR
- Pipeline bloqueia deploy se vulnerabilidades CRITICAL encontradas

---

## Compliance

### NIS2 (Diretiva EU 2022/2555)
Este projeto implementa controlos alinhados com NIS2:
- [ ] Gestão de vulnerabilidades automática (pipeline CI/CD)
- [ ] Monitorização contínua de CVEs (scan agendado diário)
- [ ] Resposta a incidentes documentada (este ficheiro)
- [ ] Supply chain security (SCA em cada build)
- [ ] Logs de auditoria (pipeline logs no GitHub Actions)

### OWASP Top 10 (2021)
Vulnerabilidades verificadas automaticamente:
- A01: Broken Access Control → require_api_key decorator
- A02: Cryptographic Failures → Bandit B303/B324, regras Semgrep
- A03: Injection → Bandit B608, Semgrep sql-injection-fstring
- A05: Security Misconfiguration → Trivy IaC scan, Semgrep flask-debug-true
- A06: Vulnerable Components → pip-audit, Trivy
- A07: Auth Failures → testes de autenticação automatizados
- A08: Software Integrity → Container scan, SBOM gerado
- A09: Logging Failures → Semgrep sensitive-data-in-logs

---

## Contactos de Segurança

| Papel | Contacto |
|-------|----------|
| Security Lead | security@example.com |
| CISO | ciso@example.com |
| Bug Bounty | https://example.com/bug-bounty |

**PGP Fingerprint:** `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

---

## Histórico de Security Advisories

| Data | CVE/ID | Severidade | Status |
|------|--------|------------|--------|
| — | — | — | Nenhum até à data |

---

*Última atualização: 2024-06-01*
*Próxima revisão: 2024-09-01*
