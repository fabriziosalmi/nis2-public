# Per Iniziare

## Prerequisiti

- Docker e Docker Compose
- Git

## Avvio Rapido

1. **Clona il repository:**

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
```

2. **Crea il file di ambiente:**

```bash
cp .env.example .env
```

Modifica `.env` e imposta `JWT_SECRET` e `NEXTAUTH_SECRET` con valori casuali. Consulta [Configurazione](./configuration.md) per tutte le variabili.

3. **Avvia la piattaforma:**

```bash
make dev
```

Questo comando compila e avvia tutti i servizi: PostgreSQL, Redis, FastAPI, Celery worker, Celery Beat e il frontend Next.js.

4. **Apri la dashboard:**

- Frontend: [http://localhost:8077](http://localhost:8077)
- Documentazione API (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)

## Primi Passi

1. Registra un account dalla pagina di login. La registrazione crea automaticamente un'organizzazione e ti assegna il ruolo di amministratore.
2. Aggiungi asset: inserisci i domini o gli IP che vuoi scansionare.
3. Avvia una scansione: seleziona uno o più asset e clicca su Avvia Scansione.
4. Esamina i risultati nella dashboard. Ogni risultato (finding) è mappato a un articolo NIS2 e include gravità e indicazioni per la remediation.

## Struttura del Progetto

```
nis2-public/
  packages/
    scanner/     # Scanner in Python (aiohttp, asyncio, dnspython, playwright)
    api/         # Backend FastAPI (REST API, definizioni task Celery)
    web/         # Frontend Next.js 15 (shadcn/ui, Tailwind CSS)
  infra/
    docker/      # docker-compose.dev.yml, docker-compose.prod.yml
  scripts/       # Helper per db seed e migrazioni
  docs/          # Questa documentazione (VitePress)
```

## Comandi Make

| Comando | Descrizione |
|---|---|
| `make dev` | Avvia tutti i servizi in modalità sviluppo |
| `make dev-down` | Ferma i servizi di sviluppo |
| `make dev-logs` | Mostra i log di tutti i servizi |
| `make api-logs` | Mostra i log del servizio API |
| `make web-logs` | Mostra i log del frontend |
| `make db-migrate msg="desc"` | Genera una nuova migrazione Alembic |
| `make db-upgrade` | Esegue le migrazioni del database |
| `make db-seed` | Popola il database con dati di esempio |
| `make test` | Esegue tutti i test (scanner + API) |
| `make test-scanner` | Esegue solo i test dello scanner |
| `make test-api` | Esegue solo i test dell'API |
| `make prod` | Avvia lo stack di produzione |
| `make prod-down` | Ferma lo stack di produzione |
| `make clean` | Rimuove container, volumi e cache |
