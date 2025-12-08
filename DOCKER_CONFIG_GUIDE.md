# Come Specificare File di Configurazione con Docker Compose

## Opzione 1: Variabile d'Ambiente CONFIG_FILE (Consigliata) ✅

Usa la variabile d'ambiente `CONFIG_FILE` per specificare quale file usare:

```bash
# Usa test_config.yaml
CONFIG_FILE=./test_config.yaml docker-compose up -d

# Usa config_prod.yaml
CONFIG_FILE=./config_prod.yaml docker-compose up -d

# Default: usa config.yaml (se non specifichi nulla)
docker-compose up -d
```

### Con file .env
Crea un file `.env` nella stessa directory del docker-compose.yml:

```bash
# .env
CONFIG_FILE=./test_config.yaml
```

Poi esegui normalmente:
```bash
docker-compose up -d
```

## Opzione 2: Override del Docker Compose

Crea un file `docker-compose.override.yml`:

```yaml
version: '3.8'
services:
  scanner:
    volumes:
      - ./test_config.yaml:/app/config.yaml:ro
```

Docker Compose lo caricherà automaticamente:
```bash
docker-compose up -d
```

## Opzione 3: File Compose Multipli

Specifica esplicitamente i file compose:

```bash
docker-compose -f docker-compose.yml -f docker-compose.test.yml up -d
```

Dove `docker-compose.test.yml` contiene:
```yaml
version: '3.8'
services:
  scanner:
    volumes:
      - ./test_config.yaml:/app/config.yaml:ro
```

## Opzione 4: Passare Config al Comando Scan

Anche se il volume monta un file, puoi specificarne un altro al momento della scansione:

```bash
# Avvia lo stack
docker-compose up -d

# Esegui scan con config specifica
docker-compose exec scanner python -m nis2scan.cli scan -c /app/configs/test_config.yaml
```

Assicurati che il file sia nella directory `configs/` che è montata nel container.

## Esempi Pratici

### Test Rapido
```bash
CONFIG_FILE=./test_config.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

### Produzione
```bash
CONFIG_FILE=./config_prod.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

### Sviluppo con Auto-reload
```bash
# Usa config di sviluppo
CONFIG_FILE=./config.dev.yaml docker-compose up -d

# Esegui scan multipli con config diverse
docker-compose exec scanner python -m nis2scan.cli scan -c /app/configs/test1.yaml
docker-compose exec scanner python -m nis2scan.cli scan -c /app/configs/test2.yaml
```

## Verifica Configurazione

Controlla quale file è montato:
```bash
docker-compose config | grep -A 2 "config.yaml"
```

Verifica dentro il container:
```bash
docker-compose exec scanner cat /app/config.yaml
```

## File .env Esempio

Crea `.env` nella root del progetto:

```bash
# File di configurazione da usare
CONFIG_FILE=./test_config.yaml

# Porta per il server web
WEB_PORT=8000

# Porta Prometheus
PROMETHEUS_PORT=9090

# Porta Grafana (se abilitato)
GRAFANA_PORT=3000
```

Poi usa:
```bash
docker-compose up -d
```

## Tabella Riepilogativa

| Metodo | Comando | Quando Usare |
|--------|---------|--------------|
| **CONFIG_FILE env** | `CONFIG_FILE=./test.yaml docker-compose up -d` | Cambio rapido, CI/CD |
| **.env file** | `docker-compose up -d` (con .env) | Configurazione persistente locale |
| **Override file** | `docker-compose up -d` (con override) | Setup sviluppo personalizzato |
| **Multiple -f** | `docker-compose -f a.yml -f b.yml up` | Ambienti multipli |
| **Scan -c flag** | `exec scanner ... scan -c /app/configs/x.yaml` | Test multipli senza restart |

## Best Practices

1. **Sviluppo**: Usa `.env` con `CONFIG_FILE=./test_config.yaml`
2. **CI/CD**: Usa variabile d'ambiente `CONFIG_FILE`
3. **Produzione**: Usa `CONFIG_FILE=./config_prod.yaml` o file override
4. **Test Multipli**: Monta directory `configs/` e usa flag `-c` nel comando scan
