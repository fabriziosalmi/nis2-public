<p align="center">
  <img src="https://img.shields.io/badge/NIS2-Posture%20Management-0f172a?style=for-the-badge&logo=shield&logoColor=white" alt="NIS2" />
  <br />
  <img src="https://img.shields.io/github/v/release/fabriziosalmi/nis2-public?style=flat-square&color=10b981" alt="Release" />
  <img src="https://img.shields.io/github/license/fabriziosalmi/nis2-public?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/i18n-6%20languages-3b82f6?style=flat-square" alt="i18n" />
  <img src="https://img.shields.io/badge/MCP-compatible-8b5cf6?style=flat-square" alt="MCP" />
  <img src="https://img.shields.io/badge/CI-passing-10b981?style=flat-square" alt="CI" />
</p>

# NIS2 Continuous Posture Management and Remediation Platform

Piattaforma open-source per la **gestione continua della postura NIS2**, allineata al **D.Lgs 138/2024** e alle **Determine ACN 127434/2026 e 127437/2026**. Governance framework, remediation engine con playbook strutturati, verifica automatizzata delle misure di sicurezza di base, e integrazione AI tramite Model Context Protocol.

> Progettata per CISO, DPO, consulenti NIS2 e team IT che devono colmare il gap tra compliance documentale ed esecuzione operativa reale.

---

## Posizionamento

Questo non e' uno scanner. E' una piattaforma di **Continuous Posture Management** che copre i tre pilastri della NIS2:

| Pilastro | Copertura | Peso NIS2 |
|----------|-----------|-----------|
| **Governance e Risk Management** | Checklist 30 item pesata su Art. 21, mappatura D.Lgs 138/2024, tracciamento scadenze Determina 127434 | ~40% |
| **Remediation e Execution Control** | 15+ playbook strutturati, AI copilot, stima effort/costo, workflow open/acknowledged/resolved | ~40% |
| **Verifica tecnica automatizzata** | 50+ controlli su TLS, DNS, headers, porte, certificati, con evidence collection | ~20% |

---

## Allineamento normativo

### D.Lgs 138/2024

| Articolo | Copertura |
|----------|-----------|
| **Art. 21** — Misure di gestione del rischio | Checklist governance 30 item con scoring pesato per ognuna delle 10 sottosezioni |
| **Art. 23** — Notifica incidenti CSIRT | Modulo incident reporting con tassonomia EU e template per notifica 24/72 ore |
| **Art. 18** — Supply Chain (Roadmap) | Vendor Risk Management: censimento fornitori rilevanti, valutazione rischio, import CSV |
| **Art. 20** — Categorizazione servizi | Supporto multi-organizzazione con classificazione asset per criticita' |

### Determine ACN

| Determina | Contenuto | Stato |
|-----------|-----------|-------|
| **127434/2026** | Misure di sicurezza di base, scadenze luglio 2027 | Supportato: verifica automatizzata continua delle misure tecniche |
| **127437/2026** | Elencazione fornitori rilevanti (Art. 18) | Roadmap: modulo Vendor Risk Management in sviluppo |
| **BIA ACN** | Modello Business Impact Analysis standardizzato | Roadmap: integrazione template BIA ACN alla pubblicazione |

> La piattaforma e' progettata per agevolare l'esportazione dei dati verso i template ufficiali ACN, non per sostituirsi ai portali istituzionali.

---

## Funzionalita' principali

### Governance Framework

- Checklist 30 item pesata, mappata su ogni sottosezione dell'Art. 21 D.Lgs 138/2024
- Scoring di compliance con progressione nel tempo
- Confronto tra scan per trend analysis
- Multi-tenant con isolamento per organizzazione (ideale per consulenti che gestiscono piu' clienti)
- RBAC: admin, auditor, viewer

### Remediation Engine (Continuous Execution Control)

- 15+ playbook strutturati con configurazioni pronte per Nginx, Apache, Caddy, IIS
- AI Copilot: spiegazioni contestuali via Ollama (locale) o OpenAI
- Stima effort e costo per singolo finding e per scan completo
- Workflow di stato: open → acknowledged → resolved
- MCP Server: 7 tool per Claude Desktop, Cursor, e qualsiasi client MCP compatibile

### Incident Reporting (Art. 23 CSIRT)

- Modulo di segnalazione con tassonomia EU conforme
- Template strutturato per le tre fasi di notifica (early warning 24h, incident notification 72h, final report)
- Raccolta evidenze e timeline ricostruzione dell'incidente
- Export in formato compatibile con le piattaforme di notifica

### Verifica tecnica automatizzata

- Certificati: chain validation, CT log monitoring (crt.sh), OCSP, key strength, expiry prediction
- TLS/SSL: versioni, cipher, weak protocols, health scoring 0-100
- DNS: DNSSEC, zone transfer, SPF, DMARC, DKIM, ridondanza MX
- HTTP: HSTS, CSP, X-Frame-Options, cookie flags, SRI, security.txt
- Porte: 14 porte critiche (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB)
- Resilienza: WAF/CDN detection, version disclosure, SSH hardening
- Secrets: AWS keys, GitHub tokens, chiavi private, JWT in risposta

### EU Privacy / GDPR Posture (separata dalla NIS2)

> Questi controlli verificano requisiti GDPR, ePrivacy e Codice del Consumo, non direttamente NIS2.

- P.IVA (obbligo italiano per siti commerciali)
- Privacy policy detection
- Cookie banner compliance (via Playwright)

---

## Architettura

```
packages/
  api/          # FastAPI — 14 router, async, Celery workers
  scanner/      # Engine di compliance (CLI standalone)
  web/          # Next.js 15 + shadcn/ui + next-intl (6 lingue)

docs/           # Documentazione VitePress
infra/          # Docker Compose, Caddyfile (auto-HTTPS)
```

## Quick Start

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
cp .env.example .env    # Generare secret reali (vedi commenti nel file)
make dev                # Avvia tutti i servizi

# UI:       http://localhost:8077
# API Docs: http://localhost:8000/docs
```

## Tech Stack

| Layer | Tecnologia |
|-------|-----------|
| **Frontend** | Next.js 15, React 19, shadcn/ui, Tailwind v4, Zustand, TanStack Query, Recharts, next-intl |
| **Backend** | FastAPI, SQLAlchemy (async), Pydantic v2, Celery, Redis, slowapi |
| **Database** | PostgreSQL 16 |
| **Scanner** | Python asyncio, aiohttp, dnspython, Playwright, python-whois |
| **Security** | CSP, HSTS, rate limiting, SSRF prevention, API key auth |
| **AI / MCP** | MCP Server (stdio + HTTP), Ollama/OpenAI |
| **Infra** | Docker, Caddy 2 (auto-HTTPS), GitHub Actions CI |

## Internazionalizzazione

| English | Italiano | Francais | Deutsch | Espanol | Portugues |
|---------|----------|----------|---------|---------|-----------|

200+ chiavi di traduzione. Locale switching via cookie, nessun cambio URL.

## Professional Services

Piattaforma sviluppata e mantenuta da **Fabrizio Salmi**, consulente indipendente NIS2.

| Servizio | Descrizione |
|----------|-------------|
| **Scan NIS2 privato** | Scansione white-label con report executive per il board |
| **Remediation certificati** | Gestione lifecycle TLS/SSL con CertMate e CertMate-NG |
| **Assessment readiness NIS2** | Gap analysis su tutte le 10 sottosezioni Art. 21 |
| **Incident response** | Supporto notifica CSIRT Art. 23, tassonomia, timeline |
| **Monitoring continuo** | Scan schedulati, trend analysis, report trimestrali |
| **Customizzazione piattaforma** | Deploy privato, moduli settoriali, integrazioni SIEM/SOAR |
| **Formazione** | Workshop NIS2 per board, training tecnico per team IT |

**Contatto:** [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

Tool correlati: [CertMate](https://github.com/fabriziosalmi/certmate) | [CertMate-NG](https://github.com/fabriziosalmi/certmate-ng)

## Licenza

AGPL-3.0 — vedi [LICENSE](LICENSE).

Puoi liberamente usare, modificare e deployare questa piattaforma. Se la modifichi e la offri come servizio a terzi, devi rendere disponibili le tue modifiche sotto la stessa licenza.

**Licenza commerciale / Dual License disponibile per Enterprise.** Se la tua organizzazione necessita di una licenza commerciale senza obblighi copyleft, contatta [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com).

## Link

- [Releases](https://github.com/fabriziosalmi/nis2-public/releases)
- [Issues](https://github.com/fabriziosalmi/nis2-public/issues)
- [Documentation](https://fabriziosalmi.github.io/nis2-public/)
- [Professional Services](mailto:fabrizio.salmi@gmail.com)
