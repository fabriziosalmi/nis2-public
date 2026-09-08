# Deployment

## Stack di Produzione

Il deployment di produzione utilizza `docker-compose.prod.yml` con Caddy come reverse proxy per configurare automaticamente HTTPS.

### Prerequisiti

- Un server con Docker e Docker Compose installati
- Un nome a dominio con DNS che punta al tuo server
- Le porte 80 e 443 aperte

### Passaggi

1. **Clona e configura:**

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
cp .env.example .env
```

2. **Modifica `.env` per la produzione.**

`.env.example` è il riferimento autorevole: contiene ogni variabile con la
ragione per cui conta, e copiandolo al passo 1 hai già la forma corretta. Qui
sotto c'è solo l'insieme che devi cambiare. **Non sostituire gli URL del
database con un'unica connessione da superuser**, come indicavano le versioni
precedenti di questa guida: l'API si rifiuta di avviarsi.

```bash
# Caddy lo usa per l'HTTPS automatico.
DOMAIN=nis2.tuodominio.com

# Segreti. Almeno 32 caratteri ciascuno; l'API rifiuta l'avvio su un
# segnaposto o su un valore corto, nominando la chiave che ha respinto.
JWT_SECRET=$(openssl rand -base64 32)
DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)   # seed MFA, credenziali dei canali
POSTGRES_PASSWORD=$(openssl rand -base64 24)     # identità di bootstrap/DDL
NIS2_APP_PASSWORD=$(openssl rand -base64 24)     # identità di runtime (vedi sotto)
REDIS_PASSWORD=$(openssl rand -base64 24)

# Dove il browser raggiunge l'API.
NEXT_PUBLIC_API_URL=https://nis2.tuodominio.com/api
CORS_ORIGINS=https://nis2.tuodominio.com
```

**Due identità sul database, e perché.** L'isolamento fra clienti poggia sulla
row-level security di Postgres, e Postgres la ignora incondizionatamente per i
ruoli SUPERUSER e BYPASSRLS — nemmeno `FORCE ROW LEVEL SECURITY` li vincola.
Quindi l'applicazione deve connettersi con un ruolo semplice, e qualcun altro
deve possedere lo schema:

| Variabile | Ruolo | Usata per |
|---|---|---|
| `DATABASE_URL` | `nis2_app` (NOSUPERUSER NOBYPASSRLS) | ogni richiesta e ogni task |
| `MIGRATION_DATABASE_URL` | `nis2` (bootstrap) | Alembic e il setup RLS all'avvio |

`nis2_app` viene creato alla prima inizializzazione del volume da
`infra/docker/initdb/01-create-app-role.sh`, usando `NIS2_APP_PASSWORD`. Entrambi
gli URL sono già corretti in `.env.example`: tu fornisci solo le due password.

All'avvio l'API verifica che il proprio ruolo di runtime non sia SUPERUSER né
BYPASSRLS e **si rifiuta di servire** in caso contrario, perché ogni policy RLS
sarebbe decorativa. Se devi rimandare — un deployment esistente a ruolo unico in
migrazione — imposta `RLS_SUPERUSER_OK=1` e leggi `UPGRADING.md`.

`NEXTAUTH_SECRET` e `NEXTAUTH_URL` comparivano nelle versioni precedenti di
questa guida. `next-auth` non è una dipendenza di `packages/web` e nessuno le
legge: se il tuo `.env` le contiene ancora sono inerti e puoi eliminarle.

3. **Avvia i servizi di produzione:**

```bash
make prod
```

Caddy si occuperà automaticamente di richiedere e rinnovare i certificati TLS tramite Let's Encrypt.

## Configurazione di Caddy

Caddy funge da reverse proxy instradando il traffico:

- `/` verso il frontend Next.js
- `/api/*` verso il backend FastAPI
- `/docs` e `/redoc` verso la documentazione OpenAPI

La gestione dei certificati TLS è completamente automatizzata e non richiede configurazioni manuali.

## Backup del Database

Esegui regolarmente il backup dei dati PostgreSQL:

```bash
# Effettua il dump del database
docker compose -f infra/docker/docker-compose.prod.yml exec postgres \
  pg_dump -U nis2 nis2 > backup_$(date +%Y%m%d).sql

# Ripristina dal backup
cat backup_20260101.sql | docker compose -f infra/docker/docker-compose.prod.yml exec -T postgres \
  psql -U nis2 nis2
```

Si consiglia di automatizzare il processo di backup utilizzando un cron job sull'host.

## Scalabilità dei Worker Celery

Puoi scalare il servizio dei worker Celery per gestire più scansioni contemporaneamente:

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d --scale celery-worker=4
```

Ogni processo worker è responsabile dell'esecuzione delle scansioni e della generazione dei report. Monitora la coda in Redis per stabilire quando sia opportuno aumentare il numero di worker.

## Monitoraggio

### Health Check

L'API espone due endpoint per il monitoraggio:

- `GET /api/v1/health` -- restituisce `{"status": "ok"}`. Ideale per le sonde di liveness dei load balancer.
- `GET /api/v1/health/ready` -- verifica la connettività al database e a Redis. Restituisce `{"status": "ok", "checks": {...}}` oppure `{"status": "degraded", "checks": {...}}`.

```bash
curl https://nis2.tuodominio.com/api/v1/health/ready
```

### Prometheus

Un'istanza di Prometheus è disponibile sulla porta `9099` all'interno dello stack di sviluppo. Lo scanner genera file di testo in formato `.prom` per la raccolta delle metriche. FastAPI non espone direttamente un endpoint HTTP `/metrics`.

## Aggiornamento

Per implementare una nuova versione:

```bash
git pull origin main
make prod
```

Docker Compose ricompila le immagini modificate e riavvia i servizi interessati. Avvia le migrazioni del database se necessario:

```bash
make db-upgrade
```
