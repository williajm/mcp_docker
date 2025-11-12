# Servidor MCP Docker

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Características

- **36 Herramientas Docker**: Gestión completa de contenedores, imágenes, redes, volúmenes, sistema y **Docker Compose**
- **5 Prompts de IA**: Resolución inteligente de problemas, optimización, depuración de red y análisis de seguridad
- **2 Recursos**: Logs en tiempo real de contenedores, estadísticas e información de proyectos compose
- **Seguridad de Tipos**: Type hints completos con validación Pydantic y modo estricto de mypy
- **Controles de Seguridad**: Sistema de seguridad de tres niveles (seguro/moderado/destructivo) con restricciones configurables
- **Pruebas Exhaustivas**: Cobertura de pruebas del 88%+ con pruebas unitarias y de integración
- **Python Moderno**: Construido con Python 3.11+, gestor de paquetes uv y diseño async-first

## Inicio Rápido

### Requisitos Previos

- Python 3.11 o superior
- Docker instalado y en ejecución
- Gestor de paquetes [uv](https://github.com/astral-sh/uv) (recomendado) o pip

### Instalación

#### Opción 1: Usando uvx (Recomendado)

```bash
# Ejecutar directamente sin instalación
uvx mcp-docker
```

#### Opción 2: Usando uv

```bash
# Instalar desde el código fuente
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Opción 3: Usando pip

```bash
# Instalar desde el código fuente
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Configuración

El servidor puede configurarse mediante variables de entorno o un archivo `.env`.

#### Configuración Docker Específica de Plataforma

**IMPORTANTE**: El `DOCKER_BASE_URL` debe configurarse correctamente para su plataforma:

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

#### Todas las Opciones de Configuración

```bash
# Configuración Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (predeterminado)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Timeout de API en segundos (predeterminado: 60)
export DOCKER_TLS_VERIFY=false  # Habilitar verificación TLS (predeterminado: false)
export DOCKER_TLS_CA_CERT="/ruta/a/ca.pem"  # Ruta al certificado CA (opcional)
export DOCKER_TLS_CLIENT_CERT="/ruta/a/cert.pem"  # Ruta al certificado de cliente (opcional)
export DOCKER_TLS_CLIENT_KEY="/ruta/a/key.pem"  # Ruta a la clave de cliente (opcional)

# Configuración de Seguridad
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Permitir operaciones rm, prune (predeterminado: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Permitir contenedores privilegiados (predeterminado: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Requerir confirmación (predeterminado: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Máximo operaciones concurrentes (predeterminado: 10)

# Configuración del Servidor
export MCP_SERVER_NAME="mcp-docker"  # Nombre del servidor MCP (predeterminado: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Versión del servidor MCP (predeterminado: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Nivel de registro: DEBUG, INFO, WARNING, ERROR, CRITICAL (predeterminado: INFO)
export MCP_DOCKER_LOG_PATH="/ruta/a/mcp_docker.log"  # Ruta del archivo de registro (opcional, predeterminado mcp_docker.log en el directorio de trabajo)
```

#### Usando un Archivo .env

Alternativamente, cree un archivo `.env` en el directorio de su proyecto:

```bash
# Ejemplo archivo .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Ejemplo archivo .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Configuración de Claude Desktop

Agregue a su configuración de Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Configuración básica (transporte stdio - recomendado):**

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

**Configuración Windows:**

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

### Uso Avanzado

#### Transporte SSE (HTTP)

El servidor admite transporte SSE (Server-Sent Events) sobre HTTP además del transporte stdio predeterminado:

```bash
# Ejecutar con transporte SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Opciones de línea de comandos:**

- `--transport`: Tipo de transporte (`stdio` o `sse`, predeterminado: `stdio`)
- `--host`: Host para enlazar el servidor SSE (predeterminado: `127.0.0.1`)
- `--port`: Puerto para enlazar el servidor SSE (predeterminado: `8000`)

#### Ruta de Registro Personalizada

Establezca una ubicación de archivo de registro personalizada usando la variable de entorno `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Descripción General de Herramientas

El servidor proporciona 48 herramientas organizadas en 6 categorías:

### Gestión de Contenedores (10 herramientas)

- `docker_list_containers` - Listar contenedores con filtros
- `docker_inspect_container` - Obtener información detallada del contenedor
- `docker_create_container` - Crear nuevo contenedor
- `docker_start_container` - Iniciar contenedor
- `docker_stop_container` - Detener contenedor ordenadamente
- `docker_restart_container` - Reiniciar contenedor
- `docker_remove_container` - Eliminar contenedor
- `docker_container_logs` - Obtener logs del contenedor
- `docker_exec_command` - Ejecutar comando en el contenedor
- `docker_container_stats` - Obtener estadísticas de uso de recursos

### Gestión de Docker Compose (12 herramientas)

- `docker_compose_up` - Iniciar servicios del proyecto compose
- `docker_compose_down` - Detener y eliminar servicios compose
- `docker_compose_restart` - Reiniciar servicios compose
- `docker_compose_stop` - Detener servicios compose
- `docker_compose_ps` - Listar servicios del proyecto compose
- `docker_compose_logs` - Obtener logs de servicios compose
- `docker_compose_exec` - Ejecutar comando en servicio compose
- `docker_compose_build` - Construir o reconstruir servicios compose
- `docker_compose_write_file` - Crear archivos compose en el directorio compose_files/
- `docker_compose_scale` - Escalar servicios compose
- `docker_compose_validate` - Validar sintaxis del archivo compose
- `docker_compose_config` - Obtener configuración compose resuelta

### Gestión de Imágenes (9 herramientas)

- `docker_list_images` - Listar imágenes
- `docker_inspect_image` - Obtener detalles de la imagen
- `docker_pull_image` - Descargar desde el registro
- `docker_build_image` - Construir desde Dockerfile
- `docker_push_image` - Subir al registro
- `docker_tag_image` - Etiquetar imagen
- `docker_remove_image` - Eliminar imagen
- `docker_prune_images` - Limpiar imágenes no utilizadas
- `docker_image_history` - Ver historial de capas

### Gestión de Redes (6 herramientas)

- `docker_list_networks` - Listar redes
- `docker_inspect_network` - Obtener detalles de la red
- `docker_create_network` - Crear red
- `docker_connect_container` - Conectar contenedor a la red
- `docker_disconnect_container` - Desconectar de la red
- `docker_remove_network` - Eliminar red

### Gestión de Volúmenes (5 herramientas)

- `docker_list_volumes` - Listar volúmenes
- `docker_inspect_volume` - Obtener detalles del volumen
- `docker_create_volume` - Crear volumen
- `docker_remove_volume` - Eliminar volumen
- `docker_prune_volumes` - Limpiar volúmenes no utilizados

### Herramientas del Sistema (6 herramientas)

- `docker_system_info` - Obtener información del sistema Docker
- `docker_system_df` - Estadísticas de uso de disco
- `docker_system_prune` - Limpiar todos los recursos no utilizados
- `docker_version` - Obtener información de versión de Docker
- `docker_events` - Transmitir eventos de Docker
- `docker_healthcheck` - Verificar estado del daemon Docker

## Prompts

Cinco prompts ayudan a los asistentes de IA a trabajar con Docker:

- **troubleshoot_container** - Diagnosticar problemas de contenedor con análisis de logs y configuración
- **optimize_container** - Obtener sugerencias de optimización para uso de recursos y seguridad
- **generate_compose** - Generar docker-compose.yml desde contenedores o descripciones
- **debug_networking** - Análisis profundo de problemas de red con resolución sistemática L3-L7
- **security_audit** - Análisis de seguridad completo siguiendo CIS Docker Benchmark con mapeo de cumplimiento

## Recursos

Cinco recursos proporcionan acceso en tiempo real a datos de contenedores y compose:

### Recursos de Contenedores

- **container://logs/{container_id}** - Transmitir logs del contenedor
- **container://stats/{container_id}** - Obtener estadísticas de uso de recursos

### Recursos de Compose

- **compose://config/{project_name}** - Obtener configuración del proyecto compose resuelta
- **compose://services/{project_name}** - Listar servicios en un proyecto compose
- **compose://logs/{project_name}/{service_name}** - Obtener logs de un servicio compose

## Directorio de Archivos Compose

El directorio `compose_files/` proporciona un entorno de prueba seguro para crear y probar configuraciones de Docker Compose.

### Archivos de Ejemplo

Se incluyen tres archivos de ejemplo listos para usar:

- `nginx-redis.yml` - Stack web multi-servicio (nginx + redis)
- `postgres-pgadmin.yml` - Stack de base de datos con UI de administración
- `simple-webapp.yml` - Ejemplo mínimo de servicio único

### Creación de Archivos Compose Personalizados

Use la herramienta `docker_compose_write_file` para crear archivos compose personalizados:

```python
# Claude puede crear archivos compose así:
{
  "filename": "mi-stack",  # Se guardará como user-mi-stack.yml
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

### Características de Seguridad

Todos los archivos compose escritos mediante la herramienta son:

- ✅ Restringidos solo al directorio `compose_files/`
- ✅ Automáticamente prefijados con `user-` para distinguirlos de los ejemplos
- ✅ Validados para sintaxis y estructura YAML
- ✅ Verificados para montajes de volúmenes peligrosos (/, /etc, /root, etc.)
- ✅ Validados para rangos de puertos y configuraciones de red apropiadas
- ✅ Protegidos contra ataques de recorrido de ruta

### Flujo de Trabajo de Prueba

Flujo de trabajo recomendado para probar la funcionalidad compose:

1. **Crear** un archivo compose usando `docker_compose_write_file`
2. **Validar** con `docker_compose_validate`
3. **Iniciar** servicios con `docker_compose_up`
4. **Verificar** el estado con `docker_compose_ps`
5. **Ver** logs con `docker_compose_logs`
6. **Limpiar** con `docker_compose_down`

## Sistema de Seguridad

El servidor implementa un sistema de seguridad de tres niveles:

1. **SEGURO (SAFE)** - Operaciones de solo lectura (list, inspect, logs, stats)
   - Sin restricciones
   - Siempre permitido

2. **MODERADO (MODERATE)** - Cambios de estado pero reversibles (start, stop, create)
   - Puede modificar el estado del sistema
   - Generalmente seguro

3. **DESTRUCTIVO (DESTRUCTIVE)** - Cambios permanentes (remove, prune)
   - Requiere `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Puede requerir confirmación
   - No se puede deshacer fácilmente

## Documentación

- [Referencia API](API.md) - Documentación completa de herramientas con ejemplos
- [Guía de Configuración](SETUP.md) - Detalles de instalación y configuración
- [Ejemplos de Uso](EXAMPLES.md) - Escenarios de uso práctico
- [Arquitectura](ARCHITECTURE.md) - Principios de diseño e implementación

## Desarrollo

### Configurar Entorno de Desarrollo

```bash
# Clonar repositorio
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Instalar dependencias
uv sync --group dev

# Ejecutar pruebas
uv run pytest

# Ejecutar linting
uv run ruff check src tests
uv run ruff format src tests

# Ejecutar verificación de tipos
uv run mypy src tests
```

### Ejecutar Pruebas

```bash
# Ejecutar todas las pruebas con cobertura
uv run pytest --cov=mcp_docker --cov-report=html

# Ejecutar solo pruebas unitarias
uv run pytest tests/unit/ -v

# Ejecutar pruebas de integración (requiere Docker)
uv run pytest tests/integration/ -v -m integration
```

### Estructura del Proyecto

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Punto de entrada
│       ├── server.py            # Implementación del servidor MCP
│       ├── config.py            # Gestión de configuración
│       ├── docker/              # Wrapper Docker SDK
│       ├── tools/               # Implementaciones de herramientas MCP
│       ├── resources/           # Proveedores de recursos MCP
│       ├── prompts/             # Plantillas de prompts MCP
│       └── utils/               # Utilidades (registro, validación, seguridad)
├── tests/                       # Suite de pruebas
├── docs/                        # Documentación
└── pyproject.toml              # Configuración del proyecto
```

## Requisitos

- **Python**: 3.11 o superior
- **Docker**: Cualquier versión reciente (probado con 20.10+)
- **Dependencias**:
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker para Python
  - `pydantic>=2.0.0` - Validación de datos
  - `loguru>=0.7.0` - Registro

### Estándares de Código

- Seguir las directrices de estilo PEP 8
- Usar type hints para todas las funciones
- Escribir docstrings (estilo Google)
- Mantener cobertura de pruebas del 90%+
- Pasar todas las verificaciones de linting y tipos

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulte el archivo [LICENSE](../LICENSE) para más detalles.

## Agradecimientos

- Construido con el [Model Context Protocol](https://modelcontextprotocol.io) de Anthropic
- Utiliza el [SDK Docker oficial para Python](https://docker-py.readthedocs.io/)
- Impulsado por herramientas modernas de Python: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)
