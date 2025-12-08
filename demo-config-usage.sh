#!/bin/bash
# Demo: Come usare diversi file di configurazione con docker-compose

set -e

echo "📋 Demo: Uso di file di configurazione diversi con Docker Compose"
echo ""

# Demo 1: Usando variabile d'ambiente inline
echo "1️⃣  Metodo 1: Variabile d'ambiente inline"
echo "   Comando: CONFIG_FILE=./test_config.yaml docker-compose config"
echo ""
CONFIG_FILE=./test_config.yaml docker-compose config | grep -A 2 "test_config.yaml" || echo "   ✅ test_config.yaml sarà montato"
echo ""

# Demo 2: Usando file .env
echo "2️⃣  Metodo 2: File .env"
echo "   Crea un file .env con: CONFIG_FILE=./test_config.yaml"
echo "   Poi esegui: docker-compose up -d"
echo ""

# Demo 3: Default
echo "3️⃣  Metodo 3: Default (config.yaml)"
echo "   Comando: docker-compose config (senza CONFIG_FILE)"
echo ""
docker-compose config | grep -A 2 "config.yaml" | head -3 || echo "   ✅ config.yaml sarà usato di default"
echo ""

# Demo 4: Avvio con config specifica
echo "4️⃣  Esempio Pratico: Avvio con test_config.yaml"
echo ""
echo "   CONFIG_FILE=./test_config.yaml docker-compose up -d"
echo "   docker-compose exec scanner python -m nis2scan.cli scan"
echo ""

echo "✅ Demo completata!"
echo ""
echo "📚 Per maggiori dettagli, vedi: DOCKER_CONFIG_GUIDE.md"
