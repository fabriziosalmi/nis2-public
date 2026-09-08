# Guida Rapida

## Prerequisiti

- Docker Engine 24+ e Docker Compose v2
- Git
- Sistema operativo Linux o macOS. Windows è supportato tramite WSL2.

Per la produzione:
- Un server con le porte 80 e 443 aperte
- Un nome di dominio con un record A che punta all'indirizzo IP del server

---

## Avvio in sviluppo

### 1. Clona il repository

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
```

### 2. Crea il file di configurazione

```bash
cp .env.example .env
```

Apri `.env` e imposta almeno questi due valori:

```bash
JWT_SECRET=$(openssl rand -base64 32)
DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

Sostituisci i valori segnaposto nel file con l'output di questi comandi. Tutti gli altri valori predefiniti funzionano per lo sviluppo locale. Consulta la pagina [Configurazione](./configuration.md) per il riferimento completo alle variabili.

### 3. Avvia la piattaforma

```bash
make dev
```

Questo comando compila e avvia tutti i servizi: PostgreSQL, Redis, il backend FastAPI, un Celery worker, Celery Beat (schedulatore) e il frontend Next.js. Al primo avvio, Docker scarica le immagini base e costruisce i layer locali — prevedi qualche minuto.

### 4. Apri la dashboard

| Servizio | URL |
|---|---|
| Dashboard frontend | http://localhost:8077 |
| API (Swagger UI) | http://localhost:8000/docs |
| API (ReDoc) | http://localhost:8000/redoc |

---

## Primi passi

### Registrazione

Apri http://localhost:8077 e clicca su **Registrati**. Inserisci nome, indirizzo email, password e nome dell'organizzazione. La registrazione crea l'organizzazione, assegna il ruolo `admin` e completa l'accesso automaticamente.

Non esiste un account amministratore preconfigurato — il primo utente registrato per un'organizzazione ne diventa automaticamente l'amministratore.

### Aggiungere un asset

Vai ad **Asset** nella barra laterale e clicca su **Aggiungi Asset**. Compila:

- **Nome**: un'etichetta leggibile (es. `Sito principale`)
- **Tipo di target**: `domain`, `ip`, o `cidr`
- **Valore del target**: il dominio o indirizzo effettivo (es. `esempio.it`, `192.168.1.0/24`)

Gli asset sono i target delle scansioni. Aggiungi tutti i domini e gli intervalli IP nel perimetro NIS2 dell'organizzazione.

### Dimostra di poterlo scansionare

Un asset nuovo nasce `unverified` e `POST /scans` rifiuta un target non
verificato con un 403. Il blocco è voluto: senza, qualunque account potrebbe
puntare lo scanner — scansione delle porte, tentativi di zone transfer,
richieste a `/.env` — verso infrastrutture con cui non ha alcun rapporto, e a
risponderne sarebbe chi gestisce l'istanza.

Apri l'asset e scegli il percorso adatto al target:

- **Dominio** — emetti una sfida DNS TXT, pubblica il record indicato sotto
  `_nis2-challenge.<dominio>` e premi verifica. È una prova, lo stesso
  meccanismo del DNS-01 di Let's Encrypt.
- **Indirizzo IP o intervallo CIDR** — non hanno un DNS con cui provare nulla,
  quindi un amministratore registra al loro posto una dichiarazione di autorità
  nominativa e datata, conservata nell'audit log e attribuita a chi l'ha fatta.

Gli asset creati prima dell'introduzione della verifica hanno stato `legacy` e
continuano a funzionare.

### Eseguire una scansione

Vai a **Scansioni** e clicca su **Nuova Scansione**. Seleziona uno o più asset e clicca su **Avvia Scansione**. La scansione viene messa in coda come task Celery ed eseguita in modo asincrono. Lo stato si aggiorna automaticamente: `pending` → `running` → `completed`.

### Analizzare i finding

Apri **Finding** a scansione completata. Ogni finding è mappato a un sotto-paragrafo dell'Art. 21 NIS2, ha una gravità (critical / high / medium / low / info) e include una descrizione e indicazioni di remediation. Aggiorna lo stato del finding (`acknowledged`, `in_progress`, `resolved`, `accepted_risk`) per tracciare l'avanzamento della remediation.

---

## Struttura del progetto

```
nis2-public/
  packages/
    scanner/    Scanner Python — aiohttp, asyncio, dnspython, playwright
    api/        Backend FastAPI — REST API, definizioni task Celery, migrazioni Alembic
    web/        Frontend Next.js 15 — shadcn/ui, Tailwind CSS
  infra/
    docker/     docker-compose.dev.yml, docker-compose.prod.yml, Caddyfile
  scripts/      Helper per seed e migrazioni database
  docs/         Sorgenti documentazione VitePress
```

---

## Comandi Make

| Comando | Descrizione |
|---|---|
| `make dev` | Compila e avvia tutti i servizi in modalità sviluppo |
| `make dev-down` | Ferma i servizi di sviluppo |
| `make dev-logs` | Mostra i log in streaming di tutti i servizi |
| `make api-logs` | Mostra i log solo del servizio API |
| `make web-logs` | Mostra i log solo del frontend |
| `make db-migrate msg="descrizione"` | Genera una nuova migrazione Alembic |
| `make db-upgrade` | Applica le migrazioni in sospeso |
| `make db-seed` | Popola il database con dati di esempio |
| `make test` | Esegue la suite di test completa (scanner + API) |
| `make test-scanner` | Esegue solo i test dello scanner |
| `make test-api` | Esegue solo i test dell'API |
| `make prod` | Avvia lo stack di produzione (Caddy con HTTPS automatico) |
| `make prod-down` | Ferma lo stack di produzione |
| `make clean` | Rimuove container, volumi e cache di build |

---

## Risoluzione dei problemi comuni

**Conflitto sulla porta 5432 (PostgreSQL)**
Se è in esecuzione un'istanza locale di PostgreSQL, fermala prima di avviare lo stack, oppure modifica la mappatura della porta nell'host in `infra/docker/docker-compose.dev.yml`.

**`make dev` fallisce al primo avvio con errore database**
L'API si avvia prima che PostgreSQL sia pronto. Docker Compose gestisce questo tramite health check, ma su macchine lente potrebbe essere necessario attendere e rieseguire `make dev`, oppure monitorare i log con `make dev-logs` finché postgres non mostra `database system is ready to accept connections`.

**Modifiche a `.env` non applicate**
Riavvia il servizio interessato:
```bash
docker compose -f infra/docker/docker-compose.dev.yml restart api worker
```

Consulta [Distribuzione](./deployment.md) per la configurazione in produzione e [Configurazione](./configuration.md) per tutte le variabili d'ambiente.
