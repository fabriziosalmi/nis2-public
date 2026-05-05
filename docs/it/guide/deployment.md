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

2. **Modifica `.env` per la produzione:**

```bash
# Imposta il tuo dominio per HTTPS automatico tramite Caddy
DOMAIN=nis2.tuodominio.com

# Genera segreti crittografici sicuri
JWT_SECRET=$(openssl rand -hex 32)
NEXTAUTH_SECRET=$(openssl rand -hex 32)

# Imposta credenziali database robuste
POSTGRES_PASSWORD=la-tua-password-sicura
DATABASE_URL=postgresql+asyncpg://nis2:la-tua-password-sicura@postgres:5432/nis2
DATABASE_URL_SYNC=postgresql://nis2:la-tua-password-sicura@postgres:5432/nis2

# Aggiorna gli URL del frontend
NEXTAUTH_URL=https://nis2.tuodominio.com
NEXT_PUBLIC_API_URL=https://nis2.tuodominio.com/api
```

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
