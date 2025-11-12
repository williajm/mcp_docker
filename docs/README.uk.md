# Сервер MCP Docker

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## Можливості

- **48 інструментів Docker**: Повне управління контейнерами, образами, мережами, томами, системою та **Docker Compose**
- **5 AI-промптів**: Інтелектуальне усунення несправностей, оптимізація, налагодження мережі та аналіз безпеки
- **5 ресурсів**: Логи контейнерів у реальному часі, статистика та інформація про compose проекти
- **Типобезпека**: Повні підказки типів з валідацією Pydantic та суворим режимом mypy
- **Контроль безпеки**: Трирівнева система безпеки (безпечний/помірний/деструктивний) з налаштовуваними обмеженнями
- **Комплексне тестування**: Покриття тестами 88%+ з юніт та інтеграційними тестами
- **Сучасний Python**: Побудовано на Python 3.11+, менеджері пакетів uv та дизайні async-first

## Швидкий старт

### Передумови

- Python 3.11 або вище
- Docker встановлений та запущений
- Менеджер пакетів [uv](https://github.com/astral-sh/uv) (рекомендовано) або pip

### Встановлення

#### Варіант 1: Використання uvx (Рекомендовано)

```bash
# Запустити безпосередньо без встановлення
uvx mcp-docker
```

#### Варіант 2: Використання uv

```bash
# Встановити з вихідного коду
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Варіант 3: Використання pip

```bash
# Встановити з вихідного коду
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Налаштування

Сервер можна налаштувати через змінні середовища або файл `.env`.

#### Налаштування Docker для конкретної платформи

**ВАЖЛИВО**: `DOCKER_BASE_URL` має бути правильно налаштований для вашої платформи:

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

#### Всі параметри налаштування

```bash
# Налаштування Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (за замовчуванням)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Таймаут API в секундах (за замовчуванням: 60)
export DOCKER_TLS_VERIFY=false  # Увімкнути перевірку TLS (за замовчуванням: false)
export DOCKER_TLS_CA_CERT="/шлях/до/ca.pem"  # Шлях до CA сертифіката (опціонально)
export DOCKER_TLS_CLIENT_CERT="/шлях/до/cert.pem"  # Шлях до клієнтського сертифіката (опціонально)
export DOCKER_TLS_CLIENT_KEY="/шлях/до/key.pem"  # Шлях до клієнтського ключа (опціонально)

# Налаштування безпеки
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Дозволити операції rm, prune (за замовчуванням: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Дозволити привілейовані контейнери (за замовчуванням: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Вимагати підтвердження (за замовчуванням: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Максимум одночасних операцій (за замовчуванням: 10)

# Налаштування сервера
export MCP_SERVER_NAME="mcp-docker"  # Назва сервера MCP (за замовчуванням: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Версія сервера MCP (за замовчуванням: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Рівень логування: DEBUG, INFO, WARNING, ERROR, CRITICAL (за замовчуванням: INFO)
export MCP_DOCKER_LOG_PATH="/шлях/до/mcp_docker.log"  # Шлях до файлу логів (опціонально, за замовчуванням mcp_docker.log в робочому каталозі)
```

#### Використання файлу .env

Альтернативно, створіть файл `.env` у каталозі вашого проекту:

```bash
# Приклад файлу .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Приклад файлу .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Налаштування Claude Desktop

Додайте до вашої конфігурації Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Базова конфігурація (транспорт stdio - рекомендовано):**

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

**Конфігурація Windows:**

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

### Розширене використання

#### Транспорт SSE (HTTP)

Сервер підтримує транспорт SSE (Server-Sent Events) через HTTP на додаток до стандартного транспорту stdio:

```bash
# Запустити з транспортом SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Опції командного рядка:**

- `--transport`: Тип транспорту (`stdio` або `sse`, за замовчуванням: `stdio`)
- `--host`: Хост для прив'язки SSE сервера (за замовчуванням: `127.0.0.1`)
- `--port`: Порт для прив'язки SSE сервера (за замовчуванням: `8000`)

#### Власний шлях до логів

Встановіть власне розташування файлу логів, використовуючи змінну середовища `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Огляд інструментів

Сервер надає 48 інструментів, організованих у 6 категорій:

### Управління контейнерами (10 інструментів)

- `docker_list_containers` - Список контейнерів з фільтрами
- `docker_inspect_container` - Отримати детальну інформацію про контейнер
- `docker_create_container` - Створити новий контейнер
- `docker_start_container` - Запустити контейнер
- `docker_stop_container` - Зупинити контейнер коректно
- `docker_restart_container` - Перезапустити контейнер
- `docker_remove_container` - Видалити контейнер
- `docker_container_logs` - Отримати логи контейнера
- `docker_exec_command` - Виконати команду в контейнері
- `docker_container_stats` - Отримати статистику використання ресурсів

### Управління Docker Compose (12 інструментів)

- `docker_compose_up` - Запустити сервіси compose проекту
- `docker_compose_down` - Зупинити та видалити compose сервіси
- `docker_compose_restart` - Перезапустити compose сервіси
- `docker_compose_stop` - Зупинити compose сервіси
- `docker_compose_ps` - Список сервісів compose проекту
- `docker_compose_logs` - Отримати логи compose сервісів
- `docker_compose_exec` - Виконати команду в compose сервісі
- `docker_compose_build` - Побудувати або перебудувати compose сервіси
- `docker_compose_write_file` - Створити compose файли в каталозі compose_files/
- `docker_compose_scale` - Масштабувати compose сервіси
- `docker_compose_validate` - Перевірити синтаксис compose файлу
- `docker_compose_config` - Отримати розв'язану конфігурацію compose

### Управління образами (9 інструментів)

- `docker_list_images` - Список образів
- `docker_inspect_image` - Отримати деталі образу
- `docker_pull_image` - Завантажити з реєстру
- `docker_build_image` - Побудувати з Dockerfile
- `docker_push_image` - Відвантажити до реєстру
- `docker_tag_image` - Позначити образ тегом
- `docker_remove_image` - Видалити образ
- `docker_prune_images` - Очистити невикористані образи
- `docker_image_history` - Переглянути історію шарів

### Управління мережами (6 інструментів)

- `docker_list_networks` - Список мереж
- `docker_inspect_network` - Отримати деталі мережі
- `docker_create_network` - Створити мережу
- `docker_connect_container` - Підключити контейнер до мережі
- `docker_disconnect_container` - Від'єднати від мережі
- `docker_remove_network` - Видалити мережу

### Управління томами (5 інструментів)

- `docker_list_volumes` - Список томів
- `docker_inspect_volume` - Отримати деталі тому
- `docker_create_volume` - Створити том
- `docker_remove_volume` - Видалити том
- `docker_prune_volumes` - Очистити невикористані томи

### Системні інструменти (6 інструментів)

- `docker_system_info` - Отримати інформацію про систему Docker
- `docker_system_df` - Статистика використання диска
- `docker_system_prune` - Очистити всі невикористані ресурси
- `docker_version` - Отримати інформацію про версію Docker
- `docker_events` - Транслювати події Docker
- `docker_healthcheck` - Перевірити стан демона Docker

## Промпти

П'ять промптів допомагають AI-асистентам працювати з Docker:

- **troubleshoot_container** - Діагностувати проблеми контейнера з аналізом логів та конфігурації
- **optimize_container** - Отримати рекомендації з оптимізації використання ресурсів та безпеки
- **generate_compose** - Генерувати docker-compose.yml з контейнерів або описів
- **debug_networking** - Глибинний аналіз мережевих проблем з систематичним усуненням L3-L7
- **security_audit** - Комплексний аналіз безпеки за CIS Docker Benchmark з картою відповідності

### Промпти для Compose

- **troubleshoot_compose_stack** - Діагностувати проблеми Docker Compose проектів та залежностей сервісів
- **optimize_compose_config** - Оптимізувати конфігурацію compose для продуктивності, надійності та безпеки

## Ресурси

П'ять ресурсів надають доступ у реальному часі до даних контейнерів та compose:

### Ресурси контейнерів

- **container://logs/{container_id}** - Транслювати логи контейнера
- **container://stats/{container_id}** - Отримати статистику використання ресурсів

### Ресурси Compose

- **compose://config/{project_name}** - Отримати розв'язану конфігурацію compose проекту
- **compose://services/{project_name}** - Список сервісів у compose проекті
- **compose://logs/{project_name}/{service_name}** - Отримати логи з compose сервісу

## Каталог файлів Compose

Каталог `compose_files/` надає безпечне середовище для створення та тестування конфігурацій Docker Compose.

### Приклади файлів

Включено три готових до використання приклади файлів:

- `nginx-redis.yml` - Багатосервісний веб-стек (nginx + redis)
- `postgres-pgadmin.yml` - Стек бази даних з адміністративним UI
- `simple-webapp.yml` - Мінімальний приклад з одним сервісом

### Створення власних файлів Compose

Використовуйте інструмент `docker_compose_write_file` для створення власних compose файлів:

```python
# Claude може створювати compose файли так:
{
  "filename": "мій-стек",  # Буде збережено як user-мій-стек.yml
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

### Функції безпеки

Всі compose файли, записані через інструмент:

- ✅ Обмежені лише каталогом `compose_files/`
- ✅ Автоматично з префіксом `user-` для відрізнення від прикладів
- ✅ Перевірені на синтаксис і структуру YAML
- ✅ Перевірені на небезпечні монтування томів (/, /etc, /root, тощо)
- ✅ Перевірені на належні діапазони портів та конфігурації мереж
- ✅ Захищені від атак обходу шляху

### Робочий процес тестування

Рекомендований робочий процес для тестування функціональності compose:

1. **Створити** compose файл за допомогою `docker_compose_write_file`
2. **Перевірити** за допомогою `docker_compose_validate`
3. **Запустити** сервіси за допомогою `docker_compose_up`
4. **Перевірити** стан за допомогою `docker_compose_ps`
5. **Переглянути** логи за допомогою `docker_compose_logs`
6. **Очистити** за допомогою `docker_compose_down`

## Система безпеки

Сервер реалізує трирівневу систему безпеки:

1. **БЕЗПЕЧНИЙ (SAFE)** - Операції лише для читання (list, inspect, logs, stats)
   - Без обмежень
   - Завжди дозволено

2. **ПОМІРНИЙ (MODERATE)** - Зміни стану, але оборотні (start, stop, create)
   - Може змінювати стан системи
   - Загалом безпечно

3. **ДЕСТРУКТИВНИЙ (DESTRUCTIVE)** - Постійні зміни (remove, prune)
   - Потребує `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Може потребувати підтвердження
   - Не можна легко скасувати

## Документація

- [Довідник API](API.md) - Повна документація інструментів з прикладами
- [Посібник з налаштування](SETUP.md) - Деталі встановлення та налаштування
- [Приклади використання](EXAMPLES.md) - Практичні сценарії використання
- [Архітектура](ARCHITECTURE.md) - Принципи дизайну та реалізація

## Розробка

### Налаштування середовища розробки

```bash
# Клонувати репозиторій
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Встановити залежності
uv sync --group dev

# Запустити тести
uv run pytest

# Запустити лінтинг
uv run ruff check src tests
uv run ruff format src tests

# Запустити перевірку типів
uv run mypy src tests
```

### Виконання тестів

```bash
# Запустити всі тести з покриттям
uv run pytest --cov=mcp_docker --cov-report=html

# Запустити лише юніт-тести
uv run pytest tests/unit/ -v

# Запустити інтеграційні тести (потребує Docker)
uv run pytest tests/integration/ -v -m integration
```

### Структура проекту

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Точка входу
│       ├── server.py            # Реалізація сервера MCP
│       ├── config.py            # Управління конфігурацією
│       ├── docker/              # Обгортка Docker SDK
│       ├── tools/               # Реалізації інструментів MCP
│       ├── resources/           # Постачальники ресурсів MCP
│       ├── prompts/             # Шаблони промптів MCP
│       └── utils/               # Утиліти (логування, валідація, безпека)
├── tests/                       # Набір тестів
├── docs/                        # Документація
└── pyproject.toml              # Конфігурація проекту
```

## Вимоги

- **Python**: 3.11 або вище
- **Docker**: Будь-яка нещодавня версія (протестовано з 20.10+)
- **Залежності**:
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker для Python
  - `pydantic>=2.0.0` - Валідація даних
  - `loguru>=0.7.0` - Логування

### Стандарти коду

- Дотримуватися рекомендацій стилю PEP 8
- Використовувати підказки типів для всіх функцій
- Писати docstrings (стиль Google)
- Підтримувати покриття тестами 90%+
- Проходити всі перевірки лінтингу та типів

## Ліцензія

Цей проект ліцензовано за ліцензією MIT - див. файл [LICENSE](../LICENSE) для деталей.

## Подяки

- Побудовано з [Model Context Protocol](https://modelcontextprotocol.io) від Anthropic
- Використовує офіційний [Docker SDK для Python](https://docker-py.readthedocs.io/)
- Працює на сучасних інструментах Python: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)
