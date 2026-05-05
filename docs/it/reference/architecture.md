# Architettura

## Panoramica

La NIS2 Platform è un monorepo contenente tre package, orchestrati da Docker Compose.

```
Utente (Browser)
  |
  v
Caddy (reverse proxy, auto-HTTPS)
  |
  +---> Next.js 15 (frontend, porta 8077)
  |
  +---> FastAPI (API, porta 8000)
          |
          +---> PostgreSQL (storage persistente)
          +---> Redis (cache, sessioni, broker Celery)
          +---> Celery Worker (esecuzione scansioni, generazione report)
          +---> Celery Beat (invio scansioni pianificate)
                  |
                  v
              Scanner (Python, aiohttp + asyncio)
```

## Struttura del Monorepo

| Percorso | Tecnologia | Scopo |
|---|---|---|
| `packages/scanner` | Python (aiohttp, asyncio, dnspython, playwright) | Scanner con i controlli di conformità NIS2 |
| `packages/api` | FastAPI (Python) | API REST, autenticazione, definizioni task Celery |
| `packages/web` | Next.js 15, shadcn/ui | Dashboard frontend |
| `infra/docker` | Docker Compose | Orchestrazione per dev e prod, configurazione Caddy |
| `scripts/` | Python | Inserimento dati (seeding) del database, helper per migrazioni |
| `docs/` | VitePress | Questa documentazione |

## Tech Stack

| Livello | Tecnologia |
|---|---|
| Frontend | Next.js 15, React, shadcn/ui, Tailwind CSS |
| API | FastAPI, Pydantic, SQLAlchemy (async), Alembic |
| Code di Task | Celery, Celery Beat, Redis (broker + backend) |
| Database | PostgreSQL |
| Cache/Sessioni | Redis |
| Scanner | Python, aiohttp, asyncio, dnspython, playwright |
| Reverse Proxy | Caddy (auto-HTTPS via Let's Encrypt) |
| Autenticazione | JWT (access + refresh token), NextAuth |

## Flusso dei Dati

### Esecuzione della Scansione

1. L'utente crea una scansione tramite la dashboard o l'API (`POST /api/v1/scans`).
2. L'API convalida la richiesta, crea un record di scansione su PostgreSQL e invia un task Celery.
3. Il worker Celery prende in carico il task e invoca lo scanner su ciascun asset di destinazione.
4. Lo scanner esegue i controlli in parallelo utilizzando `asyncio`. Le richieste HTTP usano `aiohttp`. Le ricerche DNS utilizzano `dnspython`. L'analisi delle pagine legali sfrutta `playwright` per renderizzare la vista dal browser.
5. I risultati passano attraverso il motore di conformità, che mappa i finding sui relativi articoli NIS2 e calcola la gravità.
6. I risultati (finding) vengono salvati su PostgreSQL. Il campo `compliance_matrix` della scansione viene popolato.
7. Lo stato della scansione si aggiorna in "completata".
8. Il frontend interroga l'API e visualizza i risultati non appena sono pronti.

### Scansioni Pianificate

1. Un admin o auditor crea una pianificazione con un'espressione cron tramite la dashboard o l'API.
2. Celery Beat valuta le espressioni cron e invia i task di scansione agli orari configurati.
3. L'esecuzione segue lo stesso flusso delle scansioni manuali.

### Generazione dei Report

1. L'utente richiede un report tramite la dashboard o l'API (`POST /api/v1/reports/generate`).
2. Un task Celery genera il report nel formato richiesto (PDF, JSON, CSV).
3. Il risultato del task (che include il percorso del file) viene memorizzato su Redis come risultato del task Celery. Non esiste una tabella `reports` nel database.
4. L'utente interroga lo stato tramite `GET /api/v1/reports/status/{task_id}` e scarica il file tramite `GET /api/v1/reports/download/{task_id}`.

## Schema del Database (Tabelle)

| Tabella | Descrizione |
|---|---|
| `users` | Account utente (email, password hashata, nome completo, flag attivo) |
| `organizations` | Organizzazioni tenant (nome, slug) |
| `memberships` | Appartenenza utente-organizzazione con ruolo (admin, auditor, viewer) |
| `assets` | Obiettivi di scansione (nome, tipo target, valore target, tag) |
| `scans` | Esecuzioni di scansioni (stato, snapshot config, timestamp, matrice conformità, punteggi) |
| `scan_results` | Dati grezzi dei risultati di scansione per target per ogni scansione |
| `findings` | Risultati dei singoli controlli (gravità, articolo NIS2, categoria, stato, remediation) |
| `scan_schedules` | Scansioni pianificate tramite cron (espressione cron, config, flag attivo) |
| `api_keys` | Chiavi API generate dagli utenti per accesso programmatico |
| `notification_channels` | Configurazione dei canali di notifica per organizzazione |
| `audit_logs` | Registro di audit delle azioni degli utenti |

## Modello Multi-Tenant

L'isolamento dei dati è garantito a livello di organizzazione:

- Ogni asset, scansione, finding e pianificazione appartiene a un'organizzazione.
- Le query API vengono automaticamente delimitate (scoped) in base all'organizzazione attuale dell'utente.
- Gli utenti possono appartenere a più organizzazioni con ruoli diversi.
- Il controllo degli accessi basato sui ruoli (RBAC) restringe le azioni:
  - **Admin**: accesso completo, gestisce i membri e le impostazioni.
  - **Auditor**: esegue scansioni, visualizza tutti i dati, genera report, gestisce le pianificazioni.
  - **Viewer**: accesso in sola lettura.
