# Serwer MCP Docker

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Funkcje

- **36 Narzędzi Docker**: Kompleksowe zarządzanie kontenerami, obrazami, sieciami, wolumenami i systemem
- **5 Promptów AI**: Inteligentne rozwiązywanie problemów, optymalizacja, debugowanie sieci i analiza bezpieczeństwa
- **2 Zasoby**: Logi kontenerów w czasie rzeczywistym i statystyki zasobów
- **Bezpieczeństwo Typów**: Pełne adnotacje typów z walidacją Pydantic i trybem strict mypy
- **Kontrole Bezpieczeństwa**: Trójpoziomowy system bezpieczeństwa (bezpieczne/umiarkowane/destrukcyjne) z konfigurowalnymi ograniczeniami
- **Rozbudowane Testy**: Obszerne pokrycie testami jednostkowymi i integracyjnymi
- **Nowoczesny Python**: Zbudowany w Python 3.11+, menedżer pakietów uv i architektura async-first

## Szybki Start

### Wymagania Wstępne

- Python 3.11 lub nowszy
- Zainstalowany i działający Docker
- Menedżer pakietów [uv](https://github.com/astral-sh/uv) (zalecany) lub pip

### Instalacja

#### Opcja 1: Użycie uvx (Zalecane)

```bash
# Uruchom bezpośrednio bez instalacji
uvx mcp-docker
```

#### Opcja 2: Użycie uv

```bash
# Instalacja ze źródła
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Opcja 3: Użycie pip

```bash
# Instalacja ze źródła
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Konfiguracja

Serwer można skonfigurować za pomocą zmiennych środowiskowych lub pliku `.env`.

#### Konfiguracja Docker Specyficzna dla Platformy

**WAŻNE**: Wartość `DOCKER_BASE_URL` musi być poprawnie ustawiona dla Twojej platformy:

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

#### Wszystkie Opcje Konfiguracyjne

```bash
# Konfiguracja Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (domyślnie)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Limit czasu API w sekundach (domyślnie: 60)
export DOCKER_TLS_VERIFY=false  # Włącz weryfikację TLS (domyślnie: false)
export DOCKER_TLS_CA_CERT="/ścieżka/do/ca.pem"  # Ścieżka do certyfikatu CA (opcjonalnie)
export DOCKER_TLS_CLIENT_CERT="/ścieżka/do/cert.pem"  # Ścieżka do certyfikatu klienta (opcjonalnie)
export DOCKER_TLS_CLIENT_KEY="/ścieżka/do/key.pem"  # Ścieżka do klucza klienta (opcjonalnie)

# Konfiguracja Bezpieczeństwa
export SAFETY_ALLOW_MODERATE_OPERATIONS=true  # Zezwalaj na operacje zmieniające stan (domyślnie: true)
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Zezwalaj na operacje rm, prune (domyślnie: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Zezwalaj na kontenery uprzywilejowane (domyślnie: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Wymagaj potwierdzenia (domyślnie: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Maksymalna liczba współbieżnych operacji (domyślnie: 10)

# Konfiguracja Serwera
export MCP_SERVER_NAME="mcp-docker"  # Nazwa serwera MCP (domyślnie: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Wersja serwera MCP (domyślnie: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Poziom logowania: DEBUG, INFO, WARNING, ERROR, CRITICAL (domyślnie: INFO)
export MCP_DOCKER_LOG_PATH="/ścieżka/do/mcp_docker.log"  # Ścieżka do pliku logów (opcjonalnie, domyślnie mcp_docker.log w katalogu roboczym)
```

#### Użycie Pliku .env

Alternatywnie, utwórz plik `.env` w katalogu swojego projektu:

```bash
# Przykładowy plik .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Przykładowy plik .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Konfiguracja Claude Desktop

Dodaj do konfiguracji Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Konfiguracja podstawowa (transport stdio - zalecana):**

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

**Konfiguracja Windows:**

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

### Zaawansowane Użycie

#### Transport SSE (HTTP)

Serwer obsługuje transport SSE (Server-Sent Events) przez HTTP oprócz domyślnego transportu stdio:

```bash
# Uruchom z transportem SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Opcje linii poleceń:**

- `--transport`: Typ transportu (`stdio` lub `sse`, domyślnie: `stdio`)
- `--host`: Host dla serwera SSE (domyślnie: `127.0.0.1`)
- `--port`: Port dla serwera SSE (domyślnie: `8000`)

#### Niestandardowa Ścieżka Logów

Ustaw niestandardową lokalizację pliku logów używając zmiennej środowiskowej `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Przegląd Narzędzi

Serwer udostępnia 36 narzędzi zorganizowanych w 5 kategorii:

### Zarządzanie Kontenerami (10 narzędzi)

- `docker_list_containers` - Wyświetl kontenery z filtrami
- `docker_inspect_container` - Pobierz szczegółowe informacje o kontenerze
- `docker_create_container` - Utwórz nowy kontener
- `docker_start_container` - Uruchom kontener
- `docker_stop_container` - Zatrzymaj kontener w sposób łagodny
- `docker_restart_container` - Uruchom ponownie kontener
- `docker_remove_container` - Usuń kontener
- `docker_container_logs` - Pobierz logi kontenera
- `docker_exec_command` - Wykonaj polecenie w kontenerze
- `docker_container_stats` - Pobierz statystyki zużycia zasobów

### Zarządzanie Obrazami (9 narzędzi)

- `docker_list_images` - Wyświetl obrazy
- `docker_inspect_image` - Pobierz szczegóły obrazu
- `docker_pull_image` - Pobierz z rejestru
- `docker_build_image` - Zbuduj z Dockerfile
- `docker_push_image` - Wyślij do rejestru
- `docker_tag_image` - Oznacz obraz
- `docker_remove_image` - Usuń obraz
- `docker_prune_images` - Wyczyść nieużywane obrazy
- `docker_image_history` - Zobacz historię warstw

### Zarządzanie Sieciami (6 narzędzi)

- `docker_list_networks` - Wyświetl sieci
- `docker_inspect_network` - Pobierz szczegóły sieci
- `docker_create_network` - Utwórz sieć
- `docker_connect_container` - Podłącz kontener do sieci
- `docker_disconnect_container` - Odłącz od sieci
- `docker_remove_network` - Usuń sieć

### Zarządzanie Wolumenami (5 narzędzi)

- `docker_list_volumes` - Wyświetl wolumeny
- `docker_inspect_volume` - Pobierz szczegóły wolumenu
- `docker_create_volume` - Utwórz wolumen
- `docker_remove_volume` - Usuń wolumen
- `docker_prune_volumes` - Wyczyść nieużywane wolumeny

### Narzędzia Systemowe (6 narzędzi)

- `docker_system_info` - Pobierz informacje o systemie Docker
- `docker_system_df` - Statystyki użycia dysku
- `docker_system_prune` - Wyczyść wszystkie nieużywane zasoby
- `docker_version` - Pobierz informacje o wersji Docker
- `docker_events` - Strumieniuj zdarzenia Docker
- `docker_healthcheck` - Sprawdź stan daemona Docker

## Prompty

Pięć promptów pomaga asystentom AI pracować z Dockerem:

- **troubleshoot_container** - Diagnozuj problemy kontenera z analizą logów i konfiguracji
- **optimize_container** - Uzyskaj sugestie optymalizacji dla użycia zasobów i bezpieczeństwa
- **generate_compose** - Generuj docker-compose.yml z kontenerów lub opisów
- **debug_networking** - Dogłębna analiza problemów sieciowych z systematycznym rozwiązywaniem L3-L7
- **security_audit** - Kompleksowa analiza bezpieczeństwa zgodna z CIS Docker Benchmark z mapowaniem zgodności

## Zasoby

Dwa zasoby zapewniają dostęp w czasie rzeczywistym do danych kontenerów:

- **container://logs/{container_id}** - Strumieniuj logi kontenera
- **container://stats/{container_id}** - Pobierz statystyki zużycia zasobów

## System Bezpieczeństwa

Serwer implementuje trójpoziomowy system bezpieczeństwa z konfigurowalnymi trybami operacji:

### Poziomy Bezpieczeństwa Operacji

1. **BEZPIECZNE (SAFE)** - Operacje tylko do odczytu (list, inspect, logs, stats)
   - Brak ograniczeń
   - Zawsze dozwolone
   - Przykłady: `docker_list_containers`, `docker_inspect_image`, `docker_container_logs`

2. **UMIARKOWANE (MODERATE)** - Zmieniające stan, ale odwracalne (start, stop, create)
   - Może modyfikować stan systemu
   - Kontrolowane przez `SAFETY_ALLOW_MODERATE_OPERATIONS` (domyślnie: `true`)
   - Przykłady: `docker_create_container`, `docker_start_container`, `docker_pull_image`

3. **DESTRUKCYJNE (DESTRUCTIVE)** - Trwałe zmiany (remove, prune)
   - Nie można łatwo cofnąć
   - Wymaga `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Może wymagać potwierdzenia
   - Przykłady: `docker_remove_container`, `docker_prune_images`, `docker_system_prune`

### Tryby Bezpieczeństwa

Skonfiguruj tryb bezpieczeństwa za pomocą zmiennych środowiskowych:

**Tryb Tylko do Odczytu (Najbezpieczniejszy)** - Tylko monitorowanie i obserwacja

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

- ✅ List, inspect, logs, stats
- ❌ Create, start, stop, pull
- ❌ Remove, prune

**Tryb Domyślny (Zrównoważony)** - Rozwój i operacje

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true  # lub pomiń (domyślnie)
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

- ✅ List, inspect, logs, stats
- ✅ Create, start, stop, pull
- ❌ Remove, prune

**Tryb Pełny (Najmniej Restrykcyjny)** - Zarządzanie infrastrukturą

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
```

- ✅ List, inspect, logs, stats
- ✅ Create, start, stop, pull
- ✅ Remove, prune

> **Uwaga:** Tryb tylko do odczytu jest idealny do monitorowania, audytu i przypadków użycia obserwacyjnego, gdzie żadne zmiany stanu Docker nie powinny być dozwolone.

## Dokumentacja

- [Dokumentacja API](API.md) - Pełna dokumentacja narzędzi z przykładami
- [Przewodnik Konfiguracji](SETUP.md) - Szczegóły instalacji i konfiguracji
- [Przykłady Użycia](EXAMPLES.md) - Praktyczne scenariusze użycia
- [Architektura](ARCHITECTURE.md) - Zasady projektowania i implementacja

## Rozwój

### Konfiguracja Środowiska Deweloperskiego

```bash
# Sklonuj repozytorium
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Zainstaluj zależności
uv sync --group dev

# Uruchom testy
uv run pytest

# Uruchom linting
uv run ruff check src tests
uv run ruff format src tests

# Uruchom sprawdzanie typów
uv run mypy src tests
```

### Uruchamianie Testów

Projekt zawiera trzy poziomy testów: jednostkowe, integracyjne i end-to-end (E2E).

#### Porównanie Poziomów Testów

| Aspekt | Testy Jednostkowe | Testy Integracyjne | Testy E2E |
|--------|-------------------|---------------------|-----------|
| **Daemon Docker** | ❌ Niewymagany | ✅ Wymagany | ✅ Wymagany |
| **Operacje Docker** | ❌ Brak | ✅ Rzeczywiste operacje | ✅ Rzeczywiste operacje |
| **Instancja Serwera** | ❌ Brak / Mockowana | ✅ Prawdziwy MCPDockerServer | ✅ Prawdziwy MCPDockerServer |
| **Klient MCP** | ❌ Brak | ❌ Bezpośrednie wywołania serwera | ✅ Prawdziwa ClientSession |
| **Warstwa Transportu** | ❌ Brak | ❌ Pominięta | ✅ Prawdziwy stdio/SSE |
| **Szybkość** | ⚡ Bardzo szybkie (<5s) | ⚡ Szybkie (~10s) | 🐌 Wolniejsze (~30-60s) |

#### Uruchamianie Różnych Poziomów Testów

```bash
# Uruchom wszystkie testy z pokryciem
uv run pytest --cov=mcp_docker --cov-report=html

# Uruchom tylko testy jednostkowe (szybkie, Docker niewymagany)
uv run pytest tests/unit/ -v

# Uruchom testy integracyjne (wymaga Dockera)
uv run pytest tests/integration/ -v -m integration

# Uruchom testy E2E (wymaga Dockera, kompleksowe)
uv run pytest tests/e2e/ -v -m e2e

# Uruchom testy E2E z pominięciem wolnych testów
uv run pytest tests/e2e/ -v -m "e2e and not slow"
```

### Struktura Projektu

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Punkt wejścia
│       ├── server.py            # Implementacja serwera MCP
│       ├── config.py            # Zarządzanie konfiguracją
│       ├── docker/              # Wrapper Docker SDK
│       ├── tools/               # Implementacje narzędzi MCP
│       ├── resources/           # Dostawcy zasobów MCP
│       ├── prompts/             # Szablony promptów MCP
│       └── utils/               # Narzędzia (logowanie, walidacja, bezpieczeństwo)
├── tests/                       # Pakiet testów
├── docs/                        # Dokumentacja
└── pyproject.toml              # Konfiguracja projektu
```

## Wymagania

- **Python**: 3.11 lub nowszy
- **Docker**: Dowolna najnowsza wersja (testowane z 20.10+)
- **Zależności**:
  - `mcp>=1.2.0` - MCP SDK
  - `docker>=7.1.0` - Docker SDK dla Python
  - `pydantic>=2.0.0` - Walidacja danych
  - `loguru>=0.7.0` - Logowanie

### Standardy Kodu

- Przestrzegaj wytycznych stylu PEP 8
- Używaj adnotacji typów dla wszystkich funkcji
- Pisz docstringi (styl Google)
- Utrzymuj wysokie pokrycie testami
- Zdawaj wszystkie sprawdzenia lintingu i typów

## Licencja

Ten projekt jest licencjonowany na licencji MIT - zobacz plik [LICENSE](../LICENSE) dla szczegółów.

## Podziękowania

- Zbudowany z użyciem [Model Context Protocol](https://modelcontextprotocol.io) od Anthropic
- Wykorzystuje oficjalny [Docker SDK dla Python](https://docker-py.readthedocs.io/)
- Napędzany przez nowoczesne narzędzia Python: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Mapa Drogowa

- [ ] Operacje Docker Swarm
- [ ] Obsługa zdalnych hostów Docker
- [ ] Ulepszone strumieniowanie (postęp build/pull)
- [ ] Opcja transportu WebSocket
- [ ] Integracja z Docker Scout
