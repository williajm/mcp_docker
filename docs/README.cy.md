# Gweinydd Docker MCP

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Nodweddion

- **36 o Offer Docker**: Rheolaeth gyflawn ar gynwysyddion, delweddau, rhwydweithiau, cyfrolau, a'r system
- **5 Anogiad AI**: Datrys problemau deallus, optimeiddio, dadfygio rhwydweithio, a dadansoddi diogelwch
- **2 Adnodd**: Cofnodion cynwysydd amser real ac ystadegau adnoddau
- **Diogelwch Math**: Awgrymiadau math llawn gyda dilysu Pydantic a modd llym mypy
- **Rheolyddion Diogelwch**: System diogelwch tri lefel (diogel/cymedrol/dinistriol) gyda chyfyngiadau ffurfweddiadwy
- **Profion Cynhwysfawr**: Cwmpas prawf helaeth gyda phrofion uned, integreiddio, E2E, a fuzz
- **Ffwzialu Parhaus**: Integreiddiad ClusterFuzzLite ar gyfer diogelwch a chadernid (yn cydymffurfio â Scorecard OpenSSF)
- **Python Modern**: Wedi'i adeiladu gyda Python 3.11+, rheolwr pecynnau uv, a dyluniad async-yn-gyntaf

## Dechrau Cyflym

### Rhagofynion

- Python 3.11 neu uwch
- Docker wedi'i osod ac yn rhedeg
- Rheolwr pecynnau [uv](https://github.com/astral-sh/uv) (argymhelledig) neu pip

### Gosod

#### Opsiwn 1: Defnyddio uvx (Argymhelledig)

```bash
# Rhedeg yn uniongyrchol heb osod
uvx mcp-docker
```

#### Opsiwn 2: Defnyddio uv

```bash
# Gosod o'r ffynhonnell
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Opsiwn 3: Defnyddio pip

```bash
# Gosod o'r ffynhonnell
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Ffurfweddiad

Gellir ffurfweddu'r gweinydd trwy newidynnau amgylchedd neu ffeil `.env`.

#### Ffurfweddiad Docker Penodol i'r Platfform

**PWYSIG**: Rhaid gosod `DOCKER_BASE_URL` yn gywir ar gyfer eich platfform:

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

#### Pob Opsiwn Ffurfweddu

```bash
# Ffurfweddiad Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (rhagosodiad)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Amser allan API mewn eiliadau (rhagosodiad: 60)
export DOCKER_TLS_VERIFY=false  # Galluogi gwirio TLS (rhagosodiad: false)
export DOCKER_TLS_CA_CERT="/path/to/ca.pem"  # Llwybr i dystysgrif CA (dewisol)
export DOCKER_TLS_CLIENT_CERT="/path/to/cert.pem"  # Llwybr i dystysgrif cleient (dewisol)
export DOCKER_TLS_CLIENT_KEY="/path/to/key.pem"  # Llwybr i allwedd cleient (dewisol)

# Ffurfweddiad Diogelwch
export SAFETY_ALLOW_MODERATE_OPERATIONS=true  # Caniatáu gweithrediadau sy'n newid cyflwr fel creu, cychwyn, stopio (rhagosodiad: true)
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Caniatáu gweithrediadau rm, prune (rhagosodiad: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Caniatáu cynwysyddion breintiedig (rhagosodiad: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Gofyn am gadarnhad (rhagosodiad: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Uchafswm gweithrediadau cydamserol (rhagosodiad: 10)

# Ffurfweddiad Gweinydd
export MCP_SERVER_NAME="mcp-docker"  # Enw gweinydd MCP (rhagosodiad: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Fersiwn gweinydd MCP (rhagosodiad: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Lefel cofnodi: DEBUG, INFO, WARNING, ERROR, CRITICAL (rhagosodiad: INFO)
export MCP_DOCKER_LOG_PATH="/path/to/mcp_docker.log"  # Llwybr ffeil log (dewisol, rhagosodiad i mcp_docker.log yn y cyfeiriadur gwaith)
```

#### Defnyddio Ffeil .env

Fel arall, crëwch ffeil `.env` yn eich cyfeiriadur prosiect:

```bash
# Enghraifft ffeil .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Enghraifft ffeil .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Gosodiad Claude Desktop

Ychwanegwch at eich ffurfweddiad Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Ffurfweddiad sylfaenol (cludiant stdio - argymhelledig):**

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

**Ffurfweddiad Windows:**

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

## Trosolwg Offer

Mae'r gweinydd yn darparu 36 o offer wedi'u trefnu mewn 5 categori:

### Rheoli Cynwysyddion (10 erfyn)

- `docker_list_containers` - Rhestru cynwysyddion gyda hidlwyr
- `docker_inspect_container` - Cael gwybodaeth fanwl am gynwysydd
- `docker_create_container` - Creu cynwysydd newydd
- `docker_start_container` - Cychwyn cynwysydd
- `docker_stop_container` - Stopio cynwysydd yn raslon
- `docker_restart_container` - Ailgychwyn cynwysydd
- `docker_remove_container` - Dileu cynwysydd
- `docker_container_logs` - Cael cofnodion cynwysydd
- `docker_exec_command` - Gweithredu gorchymyn mewn cynwysydd
- `docker_container_stats` - Cael ystadegau defnydd adnoddau

### Rheoli Delweddau (9 erfyn)

- `docker_list_images` - Rhestru delweddau
- `docker_inspect_image` - Cael manylion delwedd
- `docker_pull_image` - Tynnu o gofrestrfa
- `docker_build_image` - Adeiladu o Dockerfile
- `docker_push_image` - Gwthio i gofrestrfa
- `docker_tag_image` - Tagio delwedd
- `docker_remove_image` - Dileu delwedd
- `docker_prune_images` - Glanhau delweddau heb eu defnyddio
- `docker_image_history` - Gweld hanes haenau

### Rheoli Rhwydweithiau (6 erfyn)

- `docker_list_networks` - Rhestru rhwydweithiau
- `docker_inspect_network` - Cael manylion rhwydwaith
- `docker_create_network` - Creu rhwydwaith
- `docker_connect_container` - Cysylltu cynwysydd i rwydwaith
- `docker_disconnect_container` - Datgysylltu o rwydwaith
- `docker_remove_network` - Dileu rhwydwaith

### Rheoli Cyfrolau (5 erfyn)

- `docker_list_volumes` - Rhestru cyfrolau
- `docker_inspect_volume` - Cael manylion cyfrol
- `docker_create_volume` - Creu cyfrol
- `docker_remove_volume` - Dileu cyfrol
- `docker_prune_volumes` - Glanhau cyfrolau heb eu defnyddio

### Offer System (6 erfyn)

- `docker_system_info` - Cael gwybodaeth system Docker
- `docker_system_df` - Ystadegau defnydd disg
- `docker_system_prune` - Glanhau pob adnodd heb ei ddefnyddio
- `docker_version` - Cael gwybodaeth fersiwn Docker
- `docker_events` - Ffrydio digwyddiadau Docker
- `docker_healthcheck` - Gwirio iechyd daemon Docker

## Anogiadau

Mae pum anogiad yn helpu cynorthwywyr AI i weithio gyda Docker:

- **troubleshoot_container** - Diagnosio problemau cynwysydd gyda chofnodion a dadansoddi ffurfweddiad
- **optimize_container** - Cael awgrymiadau optimeiddio ar gyfer defnydd adnoddau a diogelwch
- **generate_compose** - Cynhyrchu docker-compose.yml o gynwysyddion neu ddisgrifiadau
- **debug_networking** - Dadansoddi manwl o broblemau rhwydweithio cynwysydd gyda datrys problemau systematig L3-L7
- **security_audit** - Dadansoddi diogelwch cynhwysfawr yn dilyn Mainc Prawf Docker CIS gyda mapio cydymffurfiaeth

## Adnoddau

Mae dau adnodd yn darparu mynediad amser real i ddata cynwysydd:

- **container://logs/{container_id}** - Ffrydio cofnodion cynwysydd
- **container://stats/{container_id}** - Cael ystadegau defnydd adnoddau

## System Diogelwch

Mae'r gweinydd yn gweithredu system diogelwch tri lefel gyda moddau gweithredu ffurfweddiadwy:

### Lefelau Diogelwch Gweithrediad

1. **DIOGEL** - Gweithrediadau darllen-yn-unig (rhestr, arolygu, cofnodion, ystadegau)
   - Dim cyfyngiadau
   - Caniatawyd bob amser
   - Enghreifftiau: `docker_list_containers`, `docker_inspect_image`, `docker_container_logs`

2. **CYMEDROL** - Newid cyflwr ond yn adferoladwy (cychwyn, stopio, creu)
   - Gall newid cyflwr y system
   - Wedi'i reoli gan `SAFETY_ALLOW_MODERATE_OPERATIONS` (rhagosodiad: `true`)
   - Enghreifftiau: `docker_create_container`, `docker_start_container`, `docker_pull_image`

3. **DINISTRIOL** - Newidiadau parhaol (dileu, prune)
   - Ni ellir eu dadwneud yn hawdd
   - Angen `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Gall fod angen cadarnhad
   - Enghreifftiau: `docker_remove_container`, `docker_prune_images`, `docker_system_prune`

### Moddau Diogelwch

Ffurfweddwch y modd diogelwch gan ddefnyddio newidynnau amgylchedd:

**Modd Darllen-yn-Unig (Mwyaf Diogel)** - Monitro ac arsylladwyedd yn unig

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

- ✅ Rhestr, arolygu, cofnodion, ystadegau
- ❌ Creu, cychwyn, stopio, tynnu
- ❌ Dileu, prune

**Modd Rhagosodedig (Cytbwys)** - Datblygiad a gweithrediadau

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true  # neu hepgor (rhagosodiad)
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

- ✅ Rhestr, arolygu, cofnodion, ystadegau
- ✅ Creu, cychwyn, stopio, tynnu
- ❌ Dileu, prune

**Modd Llawn (Lleiaf Cyfyngol)** - Rheoli seilwaith

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
```

- ✅ Rhestr, arolygu, cofnodion, ystadegau
- ✅ Creu, cychwyn, stopio, tynnu
- ✅ Dileu, prune

> **Nodyn:** Mae modd darllen-yn-unig yn ddelfrydol ar gyfer monitro, archwilio, ac achosion defnydd arsylladwyedd lle na ddylid caniatáu unrhyw newidiadau i gyflwr Docker.

## Dogfennaeth

- [Cyfeirnod API](docs/API.md) - Dogfennaeth offer gyflawn gydag enghreifftiau
- [Canllaw Gosod](docs/SETUP.md) - Manylion gosod a ffurfweddu
- [Enghreifftiau Defnydd](docs/EXAMPLES.md) - Senarios defnydd ymarferol
- [Pensaernïaeth](docs/ARCHITECTURE.md) - Egwyddorion dylunio a gweithrediad

## Datblygu

### Gosod Amgylchedd Datblygu

```bash
# Clonio storfa
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Gosod dibyniaethau
uv sync --group dev

# Rhedeg profion
uv run pytest

# Rhedeg linting
uv run ruff check src tests
uv run ruff format src tests

# Rhedeg gwirio mathau
uv run mypy src tests
```

### Rhedeg Profion

Mae'r prosiect yn cynnwys pedwar lefel o brofion: uned, integreiddio, pen-i-ben (E2E), a phrofion fuzz.

#### Cymhariaeth Lefelau Prawf

| Agwedd | Profion Uned | Profion Integreiddio | Profion E2E | Profion Fuzz |
|--------|-------------|---------------------|-------------|--------------|
| **Daemon Docker** | ❌ Ddim yn ofynnol | ✅ Gofynnol | ✅ Gofynnol | ❌ Ddim yn ofynnol |
| **Gweithrediadau Docker** | ❌ Dim | ✅ Gweithrediadau go iawn | ✅ Gweithrediadau go iawn | ❌ Dim |
| **Enghraifft Gweinydd** | ❌ Dim / Ffug | ✅ MCPDockerServer go iawn | ✅ MCPDockerServer go iawn | ❌ Lefel cydran |
| **Cleient MCP** | ❌ Dim | ❌ Galwadau gweinydd uniongyrchol | ✅ ClientSession go iawn | ❌ Dim |
| **Haen Cludo** | ❌ Dim | ❌ Wedi'i osgoi | ✅ stdio/SSE go iawn | ❌ Dim |
| **Pwrpas** | Rhesymeg/dilysu | Integreiddio cydrannau | Llif gwaith llawn | Diogelwch/cadernid |
| **Cyflymder** | ⚡ Cyflym iawn (<5s) | ⚡ Cyflym (~10s) | 🐌 Arafach (~30-60s) | ⚡ Parhaus (CI) |

#### Rhedeg Lefelau Prawf Gwahanol

```bash
# Rhedeg pob prawf gyda chwmpas
uv run pytest --cov=mcp_docker --cov-report=html

# Rhedeg profion uned yn unig (cyflym, dim angen Docker)
uv run pytest tests/unit/ -v

# Rhedeg profion integreiddio (angen Docker)
uv run pytest tests/integration/ -v -m integration

# Rhedeg profion E2E (angen Docker, cynhwysfawr)
uv run pytest tests/e2e/ -v -m e2e

# Rhedeg profion E2E ac eithrio profion araf
uv run pytest tests/e2e/ -v -m "e2e and not slow"

# Rhedeg profion fuzz yn lleol (angen atheris)
python3 tests/fuzz/fuzz_ssh_auth.py -atheris_runs=10000
python3 tests/fuzz/fuzz_validation.py -atheris_runs=10000
```

#### Ffwzialu

Mae'r prosiect yn defnyddio [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) ar gyfer ffwzialu parhaus i fodloni gofynion [OpenSSF Scorecard](https://github.com/ossf/scorecard). Mae profion fuzz yn rhedeg yn awtomatig mewn CI/CD i ddarganfod bregusrwydd diogelwch ac achosion ymyl. Gweler [docs/FUZZING.md](docs/FUZZING.md) am fanylion.

## Gofynion

- **Python**: 3.11 neu uwch
- **Docker**: Unrhyw fersiwn diweddar (wedi'i brofi gyda 20.10+)
- **Dibyniaethau**:
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker ar gyfer Python
  - `pydantic>=2.0.0` - Dilysu data
  - `loguru>=0.7.0` - Cofnodi

## Trwydded

Mae'r prosiect hwn wedi'i drwyddedu dan y Drwydded MIT - gweler y ffeil [LICENSE](LICENSE) am fanylion.

## Cydnabyddiaethau

- Wedi'i adeiladu gyda'r [Model Context Protocol](https://modelcontextprotocol.io) gan Anthropic
- Yn defnyddio'r [Docker SDK swyddogol ar gyfer Python](https://docker-py.readthedocs.io/)
- Wedi'i bweru gan offer Python modern: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Map Ffordd

- [ ] Gweithrediadau Docker Swarm
- [ ] Cefnogaeth gwesteiwr Docker pell
- [ ] Ffrydio gwell (cynnydd adeiladu/tynnu)
- [ ] Opsiwn cludo WebSocket
- [ ] Integreiddiad Docker Scout
