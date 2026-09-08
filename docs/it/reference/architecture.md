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

### Alert scadenze Art. 23

1. Celery Beat esegue un task di controllo scadenze ogni 15 minuti.
2. Per ogni incidente aperto, calcola il tempo rimanente alle soglie CSIRT di 24 h, 72 h e 1 mese.
3. Quando una soglia è entro 2 ore o è appena scaduta, viene inviato un alert a tutti i canali di notifica configurati (email, webhook, Slack).
4. Una chiave Redis impedisce alert duplicati per lo stesso incidente e la stessa soglia entro una finestra di deduplicazione.

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

### Come viene garantito l'isolamento

Ogni tabella visibile all'utente, eccetto `users`, `organizations`, `memberships` e le tabelle correlate all'autenticazione, porta una colonna `organization_id`. La Row-Level Security (RLS) di PostgreSQL applica l'isolamento a livello di database:

- La migrazione `002_add_rls_policies` abilita RLS e crea la policy `tenant_isolation` su tutte le tabelle tenant.
- Ogni richiesta imposta `app.current_org_id` come variabile locale di sessione PostgreSQL prima di eseguire le query.
- Il predicato della policy RLS: `organization_id::text = current_setting('app.current_org_id', true) OR current_setting('app.bypass_rls', true) = 'on'`
- Il percorso `app.bypass_rls = 'on'` è usato solo per operazioni di bootstrap (creazione utente, creazione org) nella stessa transazione, poi viene azzerato automaticamente alla chiusura della transazione.

Il ruolo applicativo del database deve essere `NOSUPERUSER NOBYPASSRLS`. I ruoli superuser bypassano RLS incondizionatamente. Se l'applicazione si connette come superuser, l'API registra un avviso e in `ENVIRONMENT=production` si rifiuta di avviarsi.

## Modello di Autenticazione

### Sessione (web)

1. `POST /auth/login` imposta tre cookie httpOnly: `access_token`, `refresh_token`, `csrf_token`.
2. Le richieste che modificano lo stato devono includere il valore di `csrf_token` come header `X-CSRF-Token` (CSRF double-submit).
3. `POST /auth/refresh` emette un nuovo access token e ruota il refresh token. I refresh token sono a uso singolo; riutilizzare un token consumato revoca l'intera famiglia (tracciamento jti in `revoked_tokens`).

### Bearer token (API / SDK)

Il JWT da qualsiasi risposta di login può essere passato anche come `Authorization: Bearer <token>`. Non è richiesto alcun cookie.

### Chiave API

Le chiavi a lunga durata con prefisso `nis2_` sono accettate sugli endpoint di lettura senza cookie. Le chiavi portano scope espliciti e vengono validati rispetto allo scope richiesto dall'endpoint ad ogni richiesta.

### TOTP MFA

Dopo la validazione della password, se l'utente ha TOTP abilitato, il flusso di login richiede un ulteriore `POST /auth/totp/verify` con un codice TOTP valido a 6 cifre prima di emettere i token.

### Supporto RS256

Quando `JWT_ALGORITHM=RS256`, i token sono firmati con la chiave privata RSA e possono essere verificati da sistemi terzi usando la chiave pubblica pubblicata a `GET /.well-known/jwks.json` in formato JWKS standard.


## Riepilogo Controlli di Sicurezza

| Controllo | Implementazione |
|---|---|
| Isolamento tenant | PostgreSQL RLS (policy `tenant_isolation`, `FORCE ROW LEVEL SECURITY`) |
| Autenticazione | JWT (HS256 o RS256), cookie httpOnly, CSRF double-submit |
| Autenticazione a due fattori | TOTP (RFC 6238) per utente |
| Integrità sessione | Rotazione refresh token con revoca per famiglia |
| Sicurezza password | Hash bcrypt, watermark `password_changed_at` per invalidazione cross-sessione |
| Rate limiting | SlowAPI su tutti gli endpoint di autenticazione e sensibili |
| Audit trail | `audit_logs` per richiesta con azione, risorsa, IP e user agent |
| Sicurezza contenuti | Content-Security-Policy, X-Frame-Options, HSTS (tramite Caddy) |
| Scope chiavi API | Enforcement scope per endpoint tramite `dual_auth_with_scope()` |
| Rilevamento segreti | gitleaks sull'intera storia git in CI |
| Audit dipendenze | pip-audit (Python) e npm audit (Node.js) in CI |
