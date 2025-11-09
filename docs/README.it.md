# Server MCP Docker

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Funzionalità

- **36 Strumenti Docker**: Gestione completa di container, immagini, reti, volumi, sistema e **Docker Compose**
- **5 Prompt AI**: Risoluzione intelligente dei problemi, ottimizzazione, debug di rete e analisi di sicurezza
- **2 Risorse**: Log in tempo reale dei container, statistiche e informazioni sui progetti compose
- **Sicurezza dei Tipi**: Type hints completi con validazione Pydantic e modalità strict di mypy
- **Controlli di Sicurezza**: Sistema di sicurezza a tre livelli (sicuro/moderato/distruttivo) con restrizioni configurabili
- **Test Completi**: Copertura dei test dell'88%+ con test unitari e di integrazione
- **Python Moderno**: Costruito con Python 3.11+, gestore di pacchetti uv e design async-first

## Avvio Rapido

### Prerequisiti

- Python 3.11 o superiore
- Docker installato e in esecuzione
- Gestore di pacchetti [uv](https://github.com/astral-sh/uv) (consigliato) o pip

### Installazione

#### Opzione 1: Utilizzo di uvx (Consigliato)

```bash
# Esegui direttamente senza installazione
uvx mcp-docker
```

#### Opzione 2: Utilizzo di uv

```bash
# Installa dal codice sorgente
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Opzione 3: Utilizzo di pip

```bash
# Installa dal codice sorgente
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Configurazione

Il server può essere configurato tramite variabili d'ambiente o un file `.env`.

#### Configurazione Docker Specifica per Piattaforma

**IMPORTANTE**: Il `DOCKER_BASE_URL` deve essere impostato correttamente per la tua piattaforma:

**Linux / macOS:**

```bash
export DOCKER_BASE_URL="unix:///var/run/docker.sock"
```

**Windows (Docker Desktop):**

```cmd
set DOCKER_BASE_URL=npipe:////./pipe/docker_engine
```

**PowerShell:**

```powershell
$env:DOCKER_BASE_URL="npipe:////./pipe/docker_engine"
```

#### Tutte le Opzioni di Configurazione

```bash
# Configurazione Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (predefinito)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Timeout API in secondi (predefinito: 60)
export DOCKER_TLS_VERIFY=false  # Abilita verifica TLS (predefinito: false)
export DOCKER_TLS_CA_CERT="/percorso/a/ca.pem"  # Percorso al certificato CA (opzionale)
export DOCKER_TLS_CLIENT_CERT="/percorso/a/cert.pem"  # Percorso al certificato client (opzionale)
export DOCKER_TLS_CLIENT_KEY="/percorso/a/key.pem"  # Percorso alla chiave client (opzionale)

# Configurazione Sicurezza
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Consenti operazioni rm, prune (predefinito: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Consenti container privilegiati (predefinito: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Richiedi conferma (predefinito: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Massimo operazioni simultanee (predefinito: 10)

# Configurazione Server
export MCP_SERVER_NAME="mcp-docker"  # Nome server MCP (predefinito: mcp-docker)
export MCP_SERVER_VERSION="0.2.0"  # Versione server MCP (predefinito: 0.2.0)
export MCP_LOG_LEVEL="INFO"  # Livello di logging: DEBUG, INFO, WARNING, ERROR, CRITICAL (predefinito: INFO)
export MCP_DOCKER_LOG_PATH="/percorso/a/mcp_docker.log"  # Percorso file di log (opzionale, predefinito mcp_docker.log nella directory di lavoro)
```

#### Utilizzo di un File .env

In alternativa, crea un file `.env` nella directory del tuo progetto:

```bash
# Esempio file .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Esempio file .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Configurazione Claude Desktop

Aggiungi alla tua configurazione Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Configurazione base (trasporto stdio - consigliato):**

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "unix:///var/run/docker.sock"
      }
    }
  }
}
```

**Configurazione Windows:**

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "npipe:////./pipe/docker_engine"
      }
    }
  }
}
```

### Utilizzo Avanzato

#### Trasporto SSE (HTTP)

Il server supporta il trasporto SSE (Server-Sent Events) su HTTP oltre al trasporto stdio predefinito:

```bash
# Esegui con trasporto SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Opzioni da riga di comando:**

- `--transport`: Tipo di trasporto (`stdio` o `sse`, predefinito: `stdio`)
- `--host`: Host per il binding del server SSE (predefinito: `127.0.0.1`)
- `--port`: Porta per il binding del server SSE (predefinito: `8000`)

#### Percorso Log Personalizzato

Imposta una posizione del file di log personalizzata utilizzando la variabile d'ambiente `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Panoramica degli Strumenti

Il server fornisce 48 strumenti organizzati in 6 categorie:

### Gestione Container (10 strumenti)

- `docker_list_containers` - Elenca i container con filtri
- `docker_inspect_container` - Ottieni informazioni dettagliate del container
- `docker_create_container` - Crea nuovo container
- `docker_start_container` - Avvia container
- `docker_stop_container` - Ferma container in modo corretto
- `docker_restart_container` - Riavvia container
- `docker_remove_container` - Rimuovi container
- `docker_container_logs` - Ottieni log del container
- `docker_exec_command` - Esegui comando nel container
- `docker_container_stats` - Ottieni statistiche utilizzo risorse

### Gestione Docker Compose (12 strumenti)

- `docker_compose_up` - Avvia servizi progetto compose
- `docker_compose_down` - Ferma e rimuovi servizi compose
- `docker_compose_restart` - Riavvia servizi compose
- `docker_compose_stop` - Ferma servizi compose
- `docker_compose_ps` - Elenca servizi progetto compose
- `docker_compose_logs` - Ottieni log servizi compose
- `docker_compose_exec` - Esegui comando in servizio compose
- `docker_compose_build` - Costruisci o ricostruisci servizi compose
- `docker_compose_write_file` - Crea file compose nella directory compose_files/
- `docker_compose_scale` - Scala servizi compose
- `docker_compose_validate` - Valida sintassi file compose
- `docker_compose_config` - Ottieni configurazione compose risolta

### Gestione Immagini (9 strumenti)

- `docker_list_images` - Elenca immagini
- `docker_inspect_image` - Ottieni dettagli immagine
- `docker_pull_image` - Scarica da registry
- `docker_build_image` - Costruisci da Dockerfile
- `docker_push_image` - Carica su registry
- `docker_tag_image` - Tagga immagine
- `docker_remove_image` - Rimuovi immagine
- `docker_prune_images` - Pulisci immagini inutilizzate
- `docker_image_history` - Visualizza cronologia layer

### Gestione Reti (6 strumenti)

- `docker_list_networks` - Elenca reti
- `docker_inspect_network` - Ottieni dettagli rete
- `docker_create_network` - Crea rete
- `docker_connect_container` - Connetti container alla rete
- `docker_disconnect_container` - Disconnetti dalla rete
- `docker_remove_network` - Rimuovi rete

### Gestione Volumi (5 strumenti)

- `docker_list_volumes` - Elenca volumi
- `docker_inspect_volume` - Ottieni dettagli volume
- `docker_create_volume` - Crea volume
- `docker_remove_volume` - Rimuovi volume
- `docker_prune_volumes` - Pulisci volumi inutilizzati

### Strumenti Sistema (6 strumenti)

- `docker_system_info` - Ottieni informazioni sistema Docker
- `docker_system_df` - Statistiche utilizzo disco
- `docker_system_prune` - Pulisci tutte le risorse inutilizzate
- `docker_version` - Ottieni informazioni versione Docker
- `docker_events` - Trasmetti eventi Docker
- `docker_healthcheck` - Verifica stato daemon Docker

## Prompt

Cinque prompt aiutano gli assistenti AI a lavorare con Docker:

- **troubleshoot_container** - Diagnostica problemi container con analisi log e configurazione
- **optimize_container** - Ottieni suggerimenti di ottimizzazione per utilizzo risorse e sicurezza
- **generate_compose** - Genera docker-compose.yml da container o descrizioni
- **debug_networking** - Analisi approfondita dei problemi di rete con risoluzione sistematica L3-L7
- **security_audit** - Analisi di sicurezza completa seguendo CIS Docker Benchmark con mappatura di conformità

## Risorse

Cinque risorse forniscono accesso in tempo reale ai dati di container e compose:

### Risorse Container

- **container://logs/{container_id}** - Trasmetti log container
- **container://stats/{container_id}** - Ottieni statistiche utilizzo risorse

### Risorse Compose

- **compose://config/{project_name}** - Ottieni configurazione progetto compose risolta
- **compose://services/{project_name}** - Elenca servizi in un progetto compose
- **compose://logs/{project_name}/{service_name}** - Ottieni log da un servizio compose

## Directory File Compose

La directory `compose_files/` fornisce un sandbox sicuro per creare e testare configurazioni Docker Compose.

### File di Esempio

Tre file di esempio pronti all'uso sono inclusi:

- `nginx-redis.yml` - Stack web multi-servizio (nginx + redis)
- `postgres-pgadmin.yml` - Stack database con UI admin
- `simple-webapp.yml` - Esempio minimo a servizio singolo

### Creazione File Compose Personalizzati

Usa lo strumento `docker_compose_write_file` per creare file compose personalizzati:

```python
# Claude può creare file compose così:
{
  "filename": "mio-stack",  # Sarà salvato come user-mio-stack.yml
  "content": {
    "version": "3.8",
    "services": {
      "web": {
        "image": "nginx:alpine",
        "ports": ["8080:80"]
      }
    }
  }
}
```

### Funzionalità di Sicurezza

Tutti i file compose scritti tramite lo strumento sono:

- ✅ Limitati solo alla directory `compose_files/`
- ✅ Automaticamente prefissati con `user-` per distinguerli dagli esempi
- ✅ Validati per sintassi e struttura YAML
- ✅ Controllati per mount di volumi pericolosi (/, /etc, /root, ecc.)
- ✅ Validati per intervalli di porte e configurazioni di rete appropriate
- ✅ Protetti contro attacchi di attraversamento del percorso

### Flusso di Lavoro Test

Flusso di lavoro consigliato per testare la funzionalità compose:

1. **Crea** un file compose usando `docker_compose_write_file`
2. **Valida** con `docker_compose_validate`
3. **Avvia** servizi con `docker_compose_up`
4. **Controlla** lo stato con `docker_compose_ps`
5. **Visualizza** log con `docker_compose_logs`
6. **Pulisci** con `docker_compose_down`

## Sistema di Sicurezza

Il server implementa un sistema di sicurezza a tre livelli:

1. **SICURO (SAFE)** - Operazioni di sola lettura (list, inspect, logs, stats)
   - Nessuna restrizione
   - Sempre consentito

2. **MODERATO (MODERATE)** - Cambiamenti di stato ma reversibili (start, stop, create)
   - Può modificare lo stato del sistema
   - Generalmente sicuro

3. **DISTRUTTIVO (DESTRUCTIVE)** - Cambiamenti permanenti (remove, prune)
   - Richiede `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Può richiedere conferma
   - Non può essere facilmente annullato

## Documentazione

- [Riferimento API](API.md) - Documentazione completa degli strumenti con esempi
- [Guida Configurazione](SETUP.md) - Dettagli installazione e configurazione
- [Esempi di Utilizzo](EXAMPLES.md) - Scenari di utilizzo pratico
- [Architettura](ARCHITECTURE.md) - Principi di design e implementazione

## Sviluppo

### Configurare Ambiente di Sviluppo

```bash
# Clona repository
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Installa dipendenze
uv sync --group dev

# Esegui test
uv run pytest

# Esegui linting
uv run ruff check src tests
uv run ruff format src tests

# Esegui controllo tipi
uv run mypy src tests
```

### Esecuzione Test

```bash
# Esegui tutti i test con copertura
uv run pytest --cov=mcp_docker --cov-report=html

# Esegui solo test unitari
uv run pytest tests/unit/ -v

# Esegui test di integrazione (richiede Docker)
uv run pytest tests/integration/ -v -m integration
```

### Struttura Progetto

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Punto di ingresso
│       ├── server.py            # Implementazione server MCP
│       ├── config.py            # Gestione configurazione
│       ├── docker/              # Wrapper Docker SDK
│       ├── tools/               # Implementazioni strumenti MCP
│       ├── resources/           # Provider risorse MCP
│       ├── prompts/             # Template prompt MCP
│       └── utils/               # Utilità (logging, validazione, sicurezza)
├── tests/                       # Suite test
├── docs/                        # Documentazione
└── pyproject.toml              # Configurazione progetto
```

## Requisiti

- **Python**: 3.11 o superiore
- **Docker**: Qualsiasi versione recente (testato con 20.10+)
- **Dipendenze**:
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker per Python
  - `pydantic>=2.0.0` - Validazione dati
  - `loguru>=0.7.0` - Logging

### Standard del Codice

- Seguire le linee guida di stile PEP 8
- Utilizzare type hints per tutte le funzioni
- Scrivere docstring (stile Google)
- Mantenere copertura test 90%+
- Superare tutti i controlli di linting e tipo

## Licenza

Questo progetto è concesso in licenza sotto la Licenza MIT - vedere il file [LICENSE](../LICENSE) per i dettagli.

## Ringraziamenti

- Costruito con il [Model Context Protocol](https://modelcontextprotocol.io) di Anthropic
- Utilizza l'[SDK Docker ufficiale per Python](https://docker-py.readthedocs.io/)
- Alimentato da strumenti Python moderni: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Roadmap

- [x] Supporto completo Docker Compose (11 strumenti, 2 prompt, 3 risorse)
- [ ] Operazioni Docker Swarm
- [ ] Supporto host Docker remoto
- [ ] Streaming migliorato (progresso build/pull)
- [ ] Opzione trasporto WebSocket
- [ ] Integrazione Docker Scout
