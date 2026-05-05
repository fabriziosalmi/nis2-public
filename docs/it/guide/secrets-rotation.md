# Rotazione dei Segreti

> **Piattaforma di Conformità NIS2 — Gestione e Rotazione dei Segreti**

## Segreti Obbligatori

| Segreto | File | Scopo | Frequenza di Rotazione |
|--------|------|---------|-------------------|
| `JWT_SECRET` | `.env` | Firma i token di accesso/aggiornamento | Ogni 90 giorni |
| `NEXTAUTH_SECRET` | `.env` | Firma i cookie di sessione di Next.js | Ogni 90 giorni |
| `POSTGRES_PASSWORD` | `.env` | Autenticazione PostgreSQL | Ogni 180 giorni |
| `REDIS_URL` | `.env` | Connessione Redis (se l'auth è abilitata) | Al bisogno |

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

### Rotazione NEXTAUTH_SECRET

**Impatto**: Tutte le sessioni del frontend vengono invalidate. Gli utenti dovranno effettuare nuovamente l'accesso.

```bash
NEW_SECRET=$(openssl rand -base64 32)
sed -i "s/^NEXTAUTH_SECRET=.*/NEXTAUTH_SECRET=$NEW_SECRET/" .env
docker compose -f infra/docker/docker-compose.prod.yml restart web
```

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
- [ ] `JWT_SECRET` e `NEXTAUTH_SECRET` hanno valori differenti

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
