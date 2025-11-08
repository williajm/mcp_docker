# Servidor MCP Docker

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml)
[![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml)
[![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml)
[![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml)
[![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![Python 3.11-3.13](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://williajm.github.io/mcp_docker/)
[![Documentation in English](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/)
[![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy)
[![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr)
[![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de)
[![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it)
[![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es)
[![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl)
[![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk)
[![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja)
[![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

Um servidor [Model Context Protocol (MCP)](https://modelcontextprotocol.io) que expõe funcionalidades do Docker para assistentes de IA como Claude. Gerencie contêineres, imagens, redes e volumes através de uma API tipada e documentada com controles de segurança.

## Funcionalidades

- **36 Ferramentas Docker**: Gerenciamento completo de contêineres, imagens, redes, volumes, sistema e **Docker Compose**
- **5 Prompts de IA**: Resolução inteligente de problemas, otimização, depuração de rede e análise de segurança
- **2 Recursos**: Logs em tempo real de contêineres, estatísticas e informações de projetos compose
- **Segurança de Tipos**: Type hints completos com validação Pydantic e modo estrito do mypy
- **Controles de Segurança**: Sistema de segurança de três níveis (seguro/moderado/destrutivo) com restrições configuráveis
- **Testes Abrangentes**: Cobertura de testes de 88%+ com testes unitários e de integração
- **Python Moderno**: Construído com Python 3.11+, gerenciador de pacotes uv e design async-first

## Início Rápido

### Pré-requisitos

- Python 3.11 ou superior
- Docker instalado e em execução
- Gerenciador de pacotes [uv](https://github.com/astral-sh/uv) (recomendado) ou pip

### Instalação

#### Opção 1: Usando uvx (Recomendado)

```bash
# Executar diretamente sem instalação
uvx mcp-docker
```

#### Opção 2: Usando uv

```bash
# Instalar do código-fonte
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Opção 3: Usando pip

```bash
# Instalar do código-fonte
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Configuração

O servidor pode ser configurado através de variáveis de ambiente ou um arquivo `.env`.

#### Configuração Docker Específica da Plataforma

**IMPORTANTE**: O `DOCKER_BASE_URL` deve ser definido corretamente para sua plataforma:

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

#### Todas as Opções de Configuração

```bash
# Configuração Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (padrão)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Timeout da API em segundos (padrão: 60)
export DOCKER_TLS_VERIFY=false  # Ativar verificação TLS (padrão: false)
export DOCKER_TLS_CA_CERT="/caminho/para/ca.pem"  # Caminho para certificado CA (opcional)
export DOCKER_TLS_CLIENT_CERT="/caminho/para/cert.pem"  # Caminho para certificado do cliente (opcional)
export DOCKER_TLS_CLIENT_KEY="/caminho/para/key.pem"  # Caminho para chave do cliente (opcional)

# Configuração de Segurança
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Permitir operações rm, prune (padrão: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Permitir contêineres privilegiados (padrão: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Exigir confirmação (padrão: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Máximo de operações simultâneas (padrão: 10)

# Configuração do Servidor
export MCP_SERVER_NAME="mcp-docker"  # Nome do servidor MCP (padrão: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Versão do servidor MCP (padrão: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Nível de log: DEBUG, INFO, WARNING, ERROR, CRITICAL (padrão: INFO)
export MCP_DOCKER_LOG_PATH="/caminho/para/mcp_docker.log"  # Caminho do arquivo de log (opcional, padrão mcp_docker.log no diretório de trabalho)
```

#### Usando um Arquivo .env

Alternativamente, crie um arquivo `.env` no diretório do seu projeto:

```bash
# Exemplo de arquivo .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Exemplo de arquivo .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Configuração do Claude Desktop

Adicione à sua configuração do Claude Desktop:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Configuração básica (transporte stdio - recomendado):**
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

**Configuração Windows:**
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

### Uso Avançado

#### Transporte SSE (HTTP)

O servidor suporta transporte SSE (Server-Sent Events) sobre HTTP além do transporte stdio padrão:

```bash
# Executar com transporte SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Opções de linha de comando:**
- `--transport`: Tipo de transporte (`stdio` ou `sse`, padrão: `stdio`)
- `--host`: Host para vincular o servidor SSE (padrão: `127.0.0.1`)
- `--port`: Porta para vincular o servidor SSE (padrão: `8000`)

#### Caminho de Log Personalizado

Defina um local de arquivo de log personalizado usando a variável de ambiente `MCP_DOCKER_LOG_PATH`:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Visão Geral das Ferramentas

O servidor fornece 48 ferramentas organizadas em 6 categorias:

### Gerenciamento de Contêineres (10 ferramentas)
- `docker_list_containers` - Listar contêineres com filtros
- `docker_inspect_container` - Obter informações detalhadas do contêiner
- `docker_create_container` - Criar novo contêiner
- `docker_start_container` - Iniciar contêiner
- `docker_stop_container` - Parar contêiner graciosamente
- `docker_restart_container` - Reiniciar contêiner
- `docker_remove_container` - Remover contêiner
- `docker_container_logs` - Obter logs do contêiner
- `docker_exec_command` - Executar comando no contêiner
- `docker_container_stats` - Obter estatísticas de uso de recursos

### Gerenciamento Docker Compose (12 ferramentas)
- `docker_compose_up` - Iniciar serviços do projeto compose
- `docker_compose_down` - Parar e remover serviços compose
- `docker_compose_restart` - Reiniciar serviços compose
- `docker_compose_stop` - Parar serviços compose
- `docker_compose_ps` - Listar serviços do projeto compose
- `docker_compose_logs` - Obter logs de serviços compose
- `docker_compose_exec` - Executar comando em serviço compose
- `docker_compose_build` - Construir ou reconstruir serviços compose
- `docker_compose_write_file` - Criar arquivos compose no diretório compose_files/
- `docker_compose_scale` - Escalar serviços compose
- `docker_compose_validate` - Validar sintaxe do arquivo compose
- `docker_compose_config` - Obter configuração compose resolvida

### Gerenciamento de Imagens (9 ferramentas)
- `docker_list_images` - Listar imagens
- `docker_inspect_image` - Obter detalhes da imagem
- `docker_pull_image` - Baixar do registro
- `docker_build_image` - Construir do Dockerfile
- `docker_push_image` - Enviar para o registro
- `docker_tag_image` - Marcar imagem
- `docker_remove_image` - Remover imagem
- `docker_prune_images` - Limpar imagens não utilizadas
- `docker_image_history` - Ver histórico de camadas

### Gerenciamento de Redes (6 ferramentas)
- `docker_list_networks` - Listar redes
- `docker_inspect_network` - Obter detalhes da rede
- `docker_create_network` - Criar rede
- `docker_connect_container` - Conectar contêiner à rede
- `docker_disconnect_container` - Desconectar da rede
- `docker_remove_network` - Remover rede

### Gerenciamento de Volumes (5 ferramentas)
- `docker_list_volumes` - Listar volumes
- `docker_inspect_volume` - Obter detalhes do volume
- `docker_create_volume` - Criar volume
- `docker_remove_volume` - Remover volume
- `docker_prune_volumes` - Limpar volumes não utilizados

### Ferramentas do Sistema (6 ferramentas)
- `docker_system_info` - Obter informações do sistema Docker
- `docker_system_df` - Estatísticas de uso de disco
- `docker_system_prune` - Limpar todos os recursos não utilizados
- `docker_version` - Obter informações da versão Docker
- `docker_events` - Transmitir eventos Docker
- `docker_healthcheck` - Verificar saúde do daemon Docker

## Prompts

Cinco prompts ajudam assistentes de IA a trabalhar com Docker:

- **troubleshoot_container** - Diagnosticar problemas de contêiner com análise de logs e configuração
- **optimize_container** - Obter sugestões de otimização para uso de recursos e segurança
- **generate_compose** - Gerar docker-compose.yml de contêineres ou descrições
- **debug_networking** - Análise profunda de problemas de rede com resolução sistemática L3-L7
- **security_audit** - Análise de segurança completa seguindo CIS Docker Benchmark com mapeamento de conformidade

## Recursos

Cinco recursos fornecem acesso em tempo real aos dados de contêineres e compose:

### Recursos de Contêineres
- **container://logs/{container_id}** - Transmitir logs do contêiner
- **container://stats/{container_id}** - Obter estatísticas de uso de recursos

### Recursos de Compose
- **compose://config/{project_name}** - Obter configuração do projeto compose resolvida
- **compose://services/{project_name}** - Listar serviços em um projeto compose
- **compose://logs/{project_name}/{service_name}** - Obter logs de um serviço compose

## Diretório de Arquivos Compose

O diretório `compose_files/` fornece um ambiente seguro para criar e testar configurações Docker Compose.

### Arquivos de Exemplo

Três arquivos de exemplo prontos para uso estão incluídos:
- `nginx-redis.yml` - Stack web multi-serviço (nginx + redis)
- `postgres-pgadmin.yml` - Stack de banco de dados com UI admin
- `simple-webapp.yml` - Exemplo mínimo de serviço único

### Criação de Arquivos Compose Personalizados

Use a ferramenta `docker_compose_write_file` para criar arquivos compose personalizados:

```python
# Claude pode criar arquivos compose assim:
{
  "filename": "minha-stack",  # Será salvo como user-minha-stack.yml
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

### Funcionalidades de Segurança

Todos os arquivos compose escritos através da ferramenta são:
- ✅ Restritos apenas ao diretório `compose_files/`
- ✅ Automaticamente prefixados com `user-` para distinguir dos exemplos
- ✅ Validados para sintaxe e estrutura YAML
- ✅ Verificados quanto a montagens de volume perigosas (/, /etc, /root, etc.)
- ✅ Validados para faixas de porta e configurações de rede apropriadas
- ✅ Protegidos contra ataques de travessia de caminho

### Fluxo de Trabalho de Teste

Fluxo de trabalho recomendado para testar funcionalidade compose:

1. **Criar** um arquivo compose usando `docker_compose_write_file`
2. **Validar** com `docker_compose_validate`
3. **Iniciar** serviços com `docker_compose_up`
4. **Verificar** status com `docker_compose_ps`
5. **Ver** logs com `docker_compose_logs`
6. **Limpar** com `docker_compose_down`

## Sistema de Segurança

O servidor implementa um sistema de segurança de três níveis:

1. **SEGURO (SAFE)** - Operações somente leitura (list, inspect, logs, stats)
   - Sem restrições
   - Sempre permitido

2. **MODERADO (MODERATE)** - Alterações de estado mas reversíveis (start, stop, create)
   - Pode modificar o estado do sistema
   - Geralmente seguro

3. **DESTRUTIVO (DESTRUCTIVE)** - Alterações permanentes (remove, prune)
   - Requer `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Pode exigir confirmação
   - Não pode ser facilmente desfeito

## Documentação

- [Referência da API](API.md) - Documentação completa das ferramentas com exemplos
- [Guia de Configuração](SETUP.md) - Detalhes de instalação e configuração
- [Exemplos de Uso](EXAMPLES.md) - Cenários de uso prático
- [Arquitetura](ARCHITECTURE.md) - Princípios de design e implementação

## Desenvolvimento

### Configurar Ambiente de Desenvolvimento

```bash
# Clonar repositório
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Instalar dependências
uv sync --group dev

# Executar testes
uv run pytest

# Executar linting
uv run ruff check src tests
uv run ruff format src tests

# Executar verificação de tipos
uv run mypy src tests
```

### Executar Testes

```bash
# Executar todos os testes com cobertura
uv run pytest --cov=mcp_docker --cov-report=html

# Executar apenas testes unitários
uv run pytest tests/unit/ -v

# Executar testes de integração (requer Docker)
uv run pytest tests/integration/ -v -m integration
```

### Estrutura do Projeto

```
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Ponto de entrada
│       ├── server.py            # Implementação do servidor MCP
│       ├── config.py            # Gerenciamento de configuração
│       ├── docker/              # Wrapper do Docker SDK
│       ├── tools/               # Implementações de ferramentas MCP
│       ├── resources/           # Provedores de recursos MCP
│       ├── prompts/             # Templates de prompts MCP
│       └── utils/               # Utilitários (logging, validação, segurança)
├── tests/                       # Suíte de testes
├── docs/                        # Documentação
└── pyproject.toml              # Configuração do projeto
```

## Requisitos

- **Python**: 3.11 ou superior
- **Docker**: Qualquer versão recente (testado com 20.10+)
- **Dependências**:
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker para Python
  - `pydantic>=2.0.0` - Validação de dados
  - `loguru>=0.7.0` - Logging

### Padrões de Código

- Seguir diretrizes de estilo PEP 8
- Usar type hints para todas as funções
- Escrever docstrings (estilo Google)
- Manter cobertura de testes de 90%+
- Passar em todas as verificações de linting e tipo

## Licença

Este projeto é licenciado sob a Licença MIT - consulte o arquivo [LICENSE](../LICENSE) para detalhes.

## Agradecimentos

- Construído com o [Model Context Protocol](https://modelcontextprotocol.io) da Anthropic
- Usa o [SDK Docker oficial para Python](https://docker-py.readthedocs.io/)
- Alimentado por ferramentas Python modernas: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Roteiro

- [x] Suporte completo ao Docker Compose (11 ferramentas, 2 prompts, 3 recursos)
- [ ] Operações Docker Swarm
- [ ] Suporte a host Docker remoto
- [ ] Streaming aprimorado (progresso de build/pull)
- [ ] Opção de transporte WebSocket
- [ ] Integração Docker Scout
