# Rotazione dei Segreti

> **Piattaforma di Conformità NIS2 — Gestione e Rotazione dei Segreti**

## Segreti Obbligatori

| Segreto | File | Scopo | Frequenza di Rotazione |
|--------|------|---------|-------------------|
| `JWT_SECRET` | `.env` | Firma i token di accesso/aggiornamento | Ogni 90 giorni |
| `DATA_ENCRYPTION_KEY` | `.env` | Cifra a riposo i seed MFA, le credenziali dei canali di notifica e le prove dei segreti trovati | Ogni 180 giorni — **leggi prima la procedura qui sotto** |
| `POSTGRES_PASSWORD` | `.env` | Autenticazione PostgreSQL | Ogni 180 giorni |
| `NIS2_APP_PASSWORD` | `.env` | Il ruolo di runtime NOSUPERUSER che rende vincolante la RLS | Ogni 180 giorni |
| `REDIS_PASSWORD` | `.env` | Autenticazione Redis (broker + contatori del rate limit) | Al bisogno |

`NEXTAUTH_SECRET` è stato rimosso nella serie 2.6.x: `next-auth` non è una
dipendenza di `packages/web` e nessuno legge quella variabile. Se il tuo `.env`
la contiene ancora è inerte e puoi eliminarla.

## Generare Segreti Sicuri

```bash
# Genera un segreto casuale a 256 bit (consigliato)
openssl rand -base64 32

# Alternativa: Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Alternativa: Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

## Procedura di Rotazione

### Rotazione JWT_SECRET

**Impatto**: Tutti i token di accesso e aggiornamento esistenti diventano non validi. Gli utenti dovranno effettuare nuovamente l'accesso.

```bash
# 1. Genera un nuovo segreto
NEW_SECRET=$(openssl rand -base64 32)

# 2. Aggiorna il file .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$NEW_SECRET/" .env

# 3. Riavvia il servizio API
docker compose -f infra/docker/docker-compose.prod.yml restart api worker

# 4. Verifica
curl -s http://localhost:8000/api/v1/health | jq .
```

**Periodo di grazia**: Non è previsto il supporto a chiavi multiple. La rotazione ha effetto immediato — tutte le sessioni vengono invalidate.

### Rotazione DATA_ENCRYPTION_KEY

**È l'unica rotazione che può causare perdita di dati se eseguita ingenuamente.**

`DATA_ENCRYPTION_KEY` cifra a riposo ogni seed TOTP/MFA, ogni credenziale dei
canali di notifica e le prove dei segreti trovati nei rilievi. Sostituirla senza
ri-cifrare rende tutto illeggibile — e fino alla 2.6.16 il fallimento era
silenzioso: il percorso di decrittazione restituiva il testo cifrato anziché
sollevare un errore, quindi l'unico sintomo era che i codici di ogni utente con
MFA smettevano di corrispondere.

Ruota con una sovrapposizione, non con uno strappo:

```bash
# 1. La vecchia chiave diventa il fallback; la nuova diventa quella corrente.
OLD_KEY=$(grep '^DATA_ENCRYPTION_KEY=' .env | cut -d= -f2-)
NEW_KEY=$(openssl rand -base64 32)
sed -i "s|^DATA_ENCRYPTION_KEY=.*|DATA_ENCRYPTION_KEY=$NEW_KEY|" .env
echo "DATA_ENCRYPTION_KEY_PREVIOUS=$OLD_KEY" >> .env

# 2. Riavvia: da qui entrambe le chiavi sono accettate in lettura, le nuove
#    scritture usano quella nuova.
docker compose -f infra/docker/docker-compose.prod.yml up -d api celery-worker

# 3. Guarda cosa verrebbe riscritto, poi riscrivilo.
make reencrypt-dry-run
make reencrypt

# 4. Togli il fallback e riavvia. Ciò che fosse sfuggito ora fallisce a voce alta.
sed -i '/^DATA_ENCRYPTION_KEY_PREVIOUS=/d' .env
docker compose -f infra/docker/docker-compose.prod.yml up -d api celery-worker
```

**Impatto**: nessuno, se segui la sequenza — nessun utente viene disconnesso e
nessuna iscrizione MFA va persa. Saltare il passo 3 fa perdere ogni iscrizione
MFA e ogni credenziale dei canali.

**Periodo di grazia**: finché `DATA_ENCRYPTION_KEY_PREVIOUS` resta impostata.
Lasciarla non danneggia la disponibilità, ma tiene la vecchia chiave su disco:
rimuovila quando il passo 3 riporta zero valori illeggibili.

### Rotazione POSTGRES_PASSWORD

**Impatto**: Richiede l'aggiornamento coordinato di PostgreSQL e del servizio API.

```bash
# 1. Connettiti a PostgreSQL e modifica la password
docker compose -f infra/docker/docker-compose.prod.yml exec db \
  psql -U nis2 -c "ALTER USER nis2 PASSWORD 'nuova_password_qui';"

# 2. Aggiorna il file .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=nuova_password_qui/" .env

# 3. Riavvia API + worker
docker compose -f infra/docker/docker-compose.prod.yml restart api worker
```

## Checklist di Sicurezza

- [ ] `.env` è presente nel file `.gitignore` e **mai tracciato in git**
- [ ] I segreti sono composti da almeno 32 caratteri generati casualmente
- [ ] Vengono usati segreti differenti per lo sviluppo e per la produzione
- [ ] I segreti vengono ruotati in caso di uscita di un membro del team
- [ ] I segreti vengono ruotati al minimo sospetto di compromissione
- [ ] In produzione i segreti sono conservati in un secrets manager (Vault, AWS SSM, ecc.) quando possibile
- [ ] `JWT_SECRET` e `DATA_ENCRYPTION_KEY` hanno valori differenti
- [ ] `DATA_ENCRYPTION_KEY` ha una copia di sicurezza in un posto diverso dal backup del database: se la si perde ogni colonna cifrata diventa illeggibile e nessun ripristino la recupera

## Raccomandazioni per la Produzione

1. **Usa un secrets manager** (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager)
2. **Imposta promemoria per la rotazione** sul tuo calendario (es. ciclo di 90 giorni)
3. **Controlla gli accessi al `.env`** — restringe i permessi di lettura al solo utente Docker:
   ```bash
   chmod 600 .env
   chown root:root .env
   ```
4. **Non loggare mai i segreti** — assicurati che la tua configurazione di log escluda le variabili d'ambiente
5. **Usa i Docker secrets** in modalità Swarm, oppure i Kubernetes secrets nei deployment K8s

### Chiave Privata RS256 (JWT_PRIVATE_KEY)

**Impatto**: tutti i token esistenti firmati con la vecchia chiave diventano non validi. La vecchia chiave pubblica deve rimanere nell'endpoint JWKS brevemente se sistemi terzi la memorizzano nella cache.

```bash
# 1. Genera una nuova coppia di chiavi
openssl genpkey -algorithm RSA -out nuova_chiave_privata.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in nuova_chiave_privata.pem -out nuova_chiave_pubblica.pem

# 2. Aggiorna JWT_PRIVATE_KEY e JWT_PUBLIC_KEY in .env

# 3. Riavvia l'API
docker compose -f infra/docker/docker-compose.prod.yml restart api
```

I sistemi terzi che memorizzano nella cache la risposta JWKS potrebbero non riuscire a verificare i nuovi token fino alla scadenza della loro cache. Se questo è un problema, mantieni entrambe le chiavi nella risposta JWKS per un periodo di TTL della cache prima di rimuovere quella vecchia.
