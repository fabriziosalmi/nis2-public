# Configurazione

Tutta la configurazione è gestita tramite variabili d'ambiente definite in `.env`. Copia `.env.example` in `.env` e adatta i valori al tuo ambiente.

## Database

| Variabile | Default | Descrizione |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://nis2:nis2secret@postgres:5432/nis2` | Stringa di connessione asincrona al database (usata da FastAPI) |
| `DATABASE_URL_SYNC` | `postgresql://nis2:nis2secret@postgres:5432/nis2` | Stringa di connessione sincrona (usata dalle migrazioni Alembic) |
| `POSTGRES_USER` | `nis2` | Utente PostgreSQL |
| `POSTGRES_PASSWORD` | `nis2secret` | Password PostgreSQL |
| `POSTGRES_DB` | `nis2` | Nome del database PostgreSQL |

## Redis

| Variabile | Default | Descrizione |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Connessione Redis per caching e sessioni |

## Autenticazione (JWT)

| Variabile | Default | Descrizione |
|---|---|---|
| `JWT_SECRET` | (cambiare in produzione) | Chiave segreta per firmare i token JWT. Generare con `openssl rand -hex 32` |
| `JWT_ALGORITHM` | `HS256` | Algoritmo di firma JWT |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Durata del token di accesso in minuti |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Durata del token di aggiornamento in giorni |

## Ripristino Password (B05)

Il flusso per dimenticare/ripristinare la password richiede un URL pubblico da inserire nel link via email e un relay SMTP (o la dev outbox) per la consegna. In `make dev` e nella suite e2e, lasciare `SMTP_HOST` vuoto attiva la dev outbox in memoria — l'email viene loggata a livello INFO e catturata per `GET /api/v1/auth/debug/last-email` (montata solo quando `ENVIRONMENT != "production"`). La produzione con `SMTP_HOST` vuoto si rifiuta di consegnare l'email: la rotta converte l'errore `RuntimeError` in un errore 5xx piuttosto che ignorare silenziosamente l'invio.

| Variabile | Default | Descrizione |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:8077` | URL di base a cui punta il link di ripristino. L'utente clicca su `${PUBLIC_URL}/reset-password?token=…` |
| `RESET_TOKEN_TTL_MINUTES` | `30` | Durata del token di ripristino. I token sono monouso; una volta consumati (quando `used_at` non è null) vengono rifiutati anche se non sono ancora scaduti |
| `SMTP_HOST` | `` (dev outbox) | Hostname del relay SMTP. Lasciare vuoto in dev / e2e — l'email viene catturata in-process |
| `SMTP_PORT` | `587` | Porta del relay SMTP |
| `SMTP_USER` | `` | Username di autenticazione SMTP (omettere se il relay non richiede l'auth) |
| `SMTP_PASSWORD` | `` | Password di autenticazione SMTP |
| `SMTP_FROM` | `noreply@nis2.local` | Header `From:` sulle email in uscita |
| `SMTP_STARTTLS` | `true` | Invia `STARTTLS` dopo l'`EHLO` (caso comune per le porte 25 / 587) |
| `SMTP_SSL` | `false` | Avvolge l'intera connessione in TLS (stile porta 465). Mutualmente esclusivo con `SMTP_STARTTLS` |

## Report

I report generati (PDF / HTML / Markdown / JSON / CSV / JUnit XML) vengono salvati in `/tmp/nis2-reports/` sul worker Celery, e sono condivisi con il container API tramite il volume Docker denominato `reports-data`. Un task Celery beat giornaliero (`cleanup-old-reports`) pulisce questa directory dai file più vecchi del TTL impostato — senza questo meccanismo, il disco si riempirebbe in modo incontrollato man mano che gli utenti generano report.

| Variabile | Default | Descrizione |
|---|---|---|
| `REPORT_TTL_DAYS` | `30` | Giorni di conservazione per i file di report prima che il task di pulizia giornaliera li elimini. Un tempo sufficiente per permettere a un team di compliance di scaricare il report della settimana precedente dopo le ferie, ma abbastanza breve da evitare che un'installazione con centinaia di scansioni al giorno riempia il disco in poche settimane. Il task di pulizia viene eseguito indipendentemente da questo valore, che si limita a stabilire l'età limite dei file da cancellare. |

## Celery

| Variabile | Default | Descrizione |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://redis:6379/1` | Message broker per Celery |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/2` | Backend per i risultati di Celery |

## Frontend (Next.js)

| Variabile | Default | Descrizione |
|---|---|---|
| `NEXTAUTH_URL` | `http://localhost:8077` | URL di base per NextAuth |
| `NEXTAUTH_SECRET` | (cambiare in produzione) | Segreto per la crittografia di NextAuth |
| `API_URL` | `http://localhost:8000` | URL dell'API interna (lato server) |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | URL pubblico dell'API (lato client) |

## Produzione (Caddy)

| Variabile | Default | Descrizione |
|---|---|---|
| `DOMAIN` | `nis2.tuodominio.com` | Dominio per la configurazione automatica di HTTPS con Caddy. Da impostare nei deployment in produzione |

## Default dello Scanner

Il comportamento dello scanner viene configurato per ogni scansione tramite l'API al momento della creazione della scansione o della pianificazione. Le impostazioni a livello di organizzazione stabiliscono i default ereditati dalle nuove scansioni. I principali parametri nell'endpoint di creazione della scansione includono:

- **Timeout**: 10 secondi per controllo (`scan_timeout`)
- **Concorrenza**: 20 task paralleli (`concurrency`)
- **Host massimi**: 0 (illimitato) -- limite configurabile per i target di ogni scansione (`max_hosts`)
- **Funzionalità**: Le singole categorie di controlli (`dns_checks`, `web_checks`, `port_scan`, `whois_checks`) possono essere attivate/disattivate per ogni scansione. Le impostazioni dell'organizzazione salvano i default che ogni nuova scansione andrà ad ereditare.

## Impostazioni dell'Organizzazione

Le impostazioni a livello organizzativo sono gestite dalla dashboard nella sezione **Impostazioni**:

- Nome dell'organizzazione e metadati
- Configurazione di default delle scansioni (funzionalità, concorrenza, timeout)
- Gestione dei membri del team (inviti, assegnazione ruoli)
- Gestione chiavi API
- Preferenze per i canali di notifica
