# MCP Docker Server

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Funktionen

- **36 Docker-Tools**: Vollständige Verwaltung von Containern, Images, Netzwerken, Volumes und System
- **5 KI-Prompts**: Intelligente Fehlersuche, Optimierung, Netzwerk-Debugging und Sicherheitsanalyse
- **2 Ressourcen**: Echtzeit-Container-Logs und Ressourcenstatistiken
- **Typsicherheit**: Vollständige Type-Hints mit Pydantic-Validierung und mypy strict mode
- **Sicherheitskontrollen**: Dreistufiges Sicherheitssystem (sicher/moderat/destruktiv) mit konfigurierbaren Einschränkungen
- **Umfassende Tests**: 88%+ Testabdeckung mit Unit- und Integrationstests
- **Modernes Python**: Entwickelt mit Python 3.11+, uv-Paketmanager und Async-First-Design

## Schnellstart

### Voraussetzungen

- Python 3.11 oder höher
- Docker installiert und ausgeführt
- [uv](https://github.com/astral-sh/uv) Paketmanager (empfohlen) oder pip

### Installation

#### Option 1: Verwendung von uvx (Empfohlen)

```bash
# Direkt ohne Installation ausführen
uvx mcp-docker
```

#### Option 2: Verwendung von uv

```bash
# Aus Quelle installieren
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Option 3: Verwendung von pip

```bash
# Aus Quelle installieren
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Konfiguration

Der Server kann über Umgebungsvariablen oder eine `.env`-Datei konfiguriert werden.

#### Plattformspezifische Docker-Konfiguration

**WICHTIG**: Die `DOCKER_BASE_URL` muss für Ihre Plattform korrekt gesetzt sein:

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

#### Alle Konfigurationsoptionen

```bash
# Docker-Konfiguration
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (Standard)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # API-Timeout in Sekunden (Standard: 60)
export DOCKER_TLS_VERIFY=false  # TLS-Überprüfung aktivieren (Standard: false)
export DOCKER_TLS_CA_CERT="/pfad/zu/ca.pem"  # Pfad zum CA-Zertifikat (optional)
export DOCKER_TLS_CLIENT_CERT="/pfad/zu/cert.pem"  # Pfad zum Client-Zertifikat (optional)
export DOCKER_TLS_CLIENT_KEY="/pfad/zu/key.pem"  # Pfad zum Client-Schlüssel (optional)

# Sicherheitskonfiguration
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # rm-, prune-Operationen erlauben (Standard: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Privilegierte Container erlauben (Standard: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Bestätigung erforderlich (Standard: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Maximale gleichzeitige Operationen (Standard: 10)

# Server-Konfiguration
export MCP_SERVER_NAME="mcp-docker"  # MCP-Servername (Standard: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # MCP-Serverversion (Standard: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Logging-Level: DEBUG, INFO, WARNING, ERROR, CRITICAL (Standard: INFO)
export MCP_DOCKER_LOG_PATH="/pfad/zu/mcp_docker.log"  # Log-Dateipfad (optional, Standard ist mcp_docker.log im Arbeitsverzeichnis)
```

#### Verwendung einer .env-Datei

Alternativ erstellen Sie eine `.env`-Datei in Ihrem Projektverzeichnis:

```bash
# .env-Datei Beispiel (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# .env-Datei Beispiel (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Claude Desktop Einrichtung

Fügen Sie dies zu Ihrer Claude Desktop-Konfiguration hinzu:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Basis-Konfiguration (stdio Transport - empfohlen):**

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

**Windows-Konfiguration:**

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

### Erweiterte Verwendung

#### SSE-Transport (HTTP)

Der Server unterstützt SSE (Server-Sent Events) Transport über HTTP zusätzlich zum Standard-stdio-Transport:

```bash
# Mit SSE-Transport ausführen
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Befehlszeilenoptionen:**

- `--transport`: Transporttyp (`stdio` oder `sse`, Standard: `stdio`)
- `--host`: Host für SSE-Server-Bindung (Standard: `127.0.0.1`)
- `--port`: Port für SSE-Server-Bindung (Standard: `8000`)

#### Benutzerdefinierter Log-Pfad

Setzen Sie einen benutzerdefinierten Log-Dateispeicherort mit der Umgebungsvariable `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Werkzeugübersicht

Der Server bietet 48 Tools, die in 6 Kategorien organisiert sind:

### Container-Verwaltung (10 Tools)

- `docker_list_containers` - Container mit Filtern auflisten
- `docker_inspect_container` - Detaillierte Container-Informationen abrufen
- `docker_create_container` - Neuen Container erstellen
- `docker_start_container` - Container starten
- `docker_stop_container` - Container ordnungsgemäß stoppen
- `docker_restart_container` - Container neu starten
- `docker_remove_container` - Container entfernen
- `docker_container_logs` - Container-Logs abrufen
- `docker_exec_command` - Befehl im Container ausführen
- `docker_container_stats` - Ressourcennutzungsstatistiken abrufen

### Docker Compose Verwaltung (12 Tools)

- `docker_compose_up` - Compose-Projekt-Services starten
- `docker_compose_down` - Compose-Services stoppen und entfernen
- `docker_compose_restart` - Compose-Services neu starten
- `docker_compose_stop` - Compose-Services stoppen
- `docker_compose_ps` - Compose-Projekt-Services auflisten
- `docker_compose_logs` - Compose-Service-Logs abrufen
- `docker_compose_exec` - Befehl in Compose-Service ausführen
- `docker_compose_build` - Compose-Services erstellen oder neu erstellen
- `docker_compose_write_file` - Compose-Dateien im Verzeichnis compose_files/ erstellen
- `docker_compose_scale` - Compose-Services skalieren
- `docker_compose_validate` - Compose-Dateisyntax validieren
- `docker_compose_config` - Aufgelöste Compose-Konfiguration abrufen

### Image-Verwaltung (9 Tools)

- `docker_list_images` - Images auflisten
- `docker_inspect_image` - Image-Details abrufen
- `docker_pull_image` - Aus Registry abrufen
- `docker_build_image` - Aus Dockerfile erstellen
- `docker_push_image` - Zu Registry hochladen
- `docker_tag_image` - Image taggen
- `docker_remove_image` - Image entfernen
- `docker_prune_images` - Ungenutzte Images bereinigen
- `docker_image_history` - Layer-Historie anzeigen

### Netzwerk-Verwaltung (6 Tools)

- `docker_list_networks` - Netzwerke auflisten
- `docker_inspect_network` - Netzwerk-Details abrufen
- `docker_create_network` - Netzwerk erstellen
- `docker_connect_container` - Container mit Netzwerk verbinden
- `docker_disconnect_container` - Vom Netzwerk trennen
- `docker_remove_network` - Netzwerk entfernen

### Volume-Verwaltung (5 Tools)

- `docker_list_volumes` - Volumes auflisten
- `docker_inspect_volume` - Volume-Details abrufen
- `docker_create_volume` - Volume erstellen
- `docker_remove_volume` - Volume entfernen
- `docker_prune_volumes` - Ungenutzte Volumes bereinigen

### System-Tools (6 Tools)

- `docker_system_info` - Docker-Systeminformationen abrufen
- `docker_system_df` - Festplattennutzungsstatistiken
- `docker_system_prune` - Alle ungenutzten Ressourcen bereinigen
- `docker_version` - Docker-Versionsinformationen abrufen
- `docker_events` - Docker-Events streamen
- `docker_healthcheck` - Docker-Daemon-Zustand überprüfen

## Prompts

Fünf Prompts helfen KI-Assistenten bei der Arbeit mit Docker:

- **troubleshoot_container** - Container-Probleme mit Log- und Konfigurationsanalyse diagnostizieren
- **optimize_container** - Optimierungsvorschläge für Ressourcennutzung und Sicherheit erhalten
- **generate_compose** - docker-compose.yml aus Containern oder Beschreibungen generieren
- **debug_networking** - Tiefgehende Netzwerkproblemanalyse mit systematischer L3-L7-Fehlersuche
- **security_audit** - Umfassende Sicherheitsanalyse nach CIS Docker Benchmark mit Compliance-Mapping

## Ressourcen

Fünf Ressourcen bieten Echtzeitzugriff auf Container- und Compose-Daten:

### Container-Ressourcen

- **container://logs/{container_id}** - Container-Logs streamen
- **container://stats/{container_id}** - Ressourcennutzungsstatistiken abrufen

### Compose-Ressourcen

- **compose://config/{project_name}** - Aufgelöste Compose-Projektkonfiguration abrufen
- **compose://services/{project_name}** - Services in einem Compose-Projekt auflisten
- **compose://logs/{project_name}/{service_name}** - Logs von einem Compose-Service abrufen

## Compose-Dateien-Verzeichnis

Das Verzeichnis `compose_files/` bietet eine sichere Sandbox zum Erstellen und Testen von Docker Compose-Konfigurationen.

### Beispieldateien

Drei einsatzbereite Beispieldateien sind enthalten:

- `nginx-redis.yml` - Multi-Service-Web-Stack (nginx + redis)
- `postgres-pgadmin.yml` - Datenbank-Stack mit Admin-UI
- `simple-webapp.yml` - Minimales Single-Service-Beispiel

### Erstellen benutzerdefinierter Compose-Dateien

Verwenden Sie das Tool `docker_compose_write_file`, um benutzerdefinierte Compose-Dateien zu erstellen:

```python
# Claude kann Compose-Dateien so erstellen:
{
  "filename": "mein-stack",  # Wird als user-mein-stack.yml gespeichert
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

### Sicherheitsfunktionen

Alle über das Tool geschriebenen Compose-Dateien sind:

- ✅ Nur auf das Verzeichnis `compose_files/` beschränkt
- ✅ Automatisch mit `user-` präfixiert, um sie von Beispielen zu unterscheiden
- ✅ Auf YAML-Syntax und -Struktur validiert
- ✅ Auf gefährliche Volume-Mounts überprüft (/, /etc, /root, etc.)
- ✅ Auf korrekte Port-Bereiche und Netzwerkkonfigurationen validiert
- ✅ Gegen Path-Traversal-Angriffe geschützt

### Test-Workflow

Empfohlener Workflow zum Testen der Compose-Funktionalität:

1. **Erstellen** Sie eine Compose-Datei mit `docker_compose_write_file`
2. **Validieren** Sie mit `docker_compose_validate`
3. **Starten** Sie Services mit `docker_compose_up`
4. **Überprüfen** Sie den Status mit `docker_compose_ps`
5. **Zeigen** Sie Logs mit `docker_compose_logs` an
6. **Bereinigen** Sie mit `docker_compose_down`

## Sicherheitssystem

Der Server implementiert ein dreistufiges Sicherheitssystem:

1. **SICHER (SAFE)** - Nur-Lese-Operationen (list, inspect, logs, stats)
   - Keine Einschränkungen
   - Immer erlaubt

2. **MODERAT (MODERATE)** - Zustandsändernd aber reversibel (start, stop, create)
   - Kann Systemzustand ändern
   - Generell sicher

3. **DESTRUKTIV (DESTRUCTIVE)** - Permanente Änderungen (remove, prune)
   - Erfordert `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Kann Bestätigung erfordern
   - Kann nicht einfach rückgängig gemacht werden

## Dokumentation

- [API-Referenz](API.md) - Vollständige Tool-Dokumentation mit Beispielen
- [Einrichtungsanleitung](SETUP.md) - Installations- und Konfigurationsdetails
- [Verwendungsbeispiele](EXAMPLES.md) - Praktische Verwendungsszenarien
- [Architektur](ARCHITECTURE.md) - Designprinzipien und Implementierung

## Entwicklung

### Entwicklungsumgebung einrichten

```bash
# Repository klonen
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Abhängigkeiten installieren
uv sync --group dev

# Tests ausführen
uv run pytest

# Linting ausführen
uv run ruff check src tests
uv run ruff format src tests

# Typprüfung ausführen
uv run mypy src tests
```

### Tests ausführen

```bash
# Alle Tests mit Abdeckung ausführen
uv run pytest --cov=mcp_docker --cov-report=html

# Nur Unit-Tests ausführen
uv run pytest tests/unit/ -v

# Integrationstests ausführen (erfordert Docker)
uv run pytest tests/integration/ -v -m integration
```

### Projektstruktur

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Einstiegspunkt
│       ├── server.py            # MCP-Server-Implementierung
│       ├── config.py            # Konfigurationsverwaltung
│       ├── docker/              # Docker SDK Wrapper
│       ├── tools/               # MCP-Tool-Implementierungen
│       ├── resources/           # MCP-Ressourcenanbieter
│       ├── prompts/             # MCP-Prompt-Templates
│       └── utils/               # Hilfsprogramme (Logging, Validierung, Sicherheit)
├── tests/                       # Test-Suite
├── docs/                        # Dokumentation
└── pyproject.toml              # Projektkonfiguration
```

## Anforderungen

- **Python**: 3.11 oder höher
- **Docker**: Jede aktuelle Version (getestet mit 20.10+)
- **Abhängigkeiten**:
  - `mcp>=1.2.0` - MCP SDK
  - `docker>=7.1.0` - Docker SDK für Python
  - `pydantic>=2.0.0` - Datenvalidierung
  - `loguru>=0.7.0` - Logging

### Code-Standards

- PEP 8-Stilrichtlinien befolgen
- Type-Hints für alle Funktionen verwenden
- Docstrings schreiben (Google-Stil)
- 90%+ Testabdeckung aufrechterhalten
- Alle Linting- und Typprüfungen bestehen

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert - siehe die Datei [LICENSE](../LICENSE) für Details.

## Danksagungen

- Entwickelt mit dem [Model Context Protocol](https://modelcontextprotocol.io) von Anthropic
- Verwendet das offizielle [Docker SDK für Python](https://docker-py.readthedocs.io/)
- Unterstützt von modernen Python-Tools: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)
