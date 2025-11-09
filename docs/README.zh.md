# MCP Docker 服务器

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## 功能特性

- **36个Docker工具**：完整管理容器、镜像、网络、卷、系统和**Docker Compose**
- **5个AI提示**：智能故障排查、优化、网络调试和安全分析
- **2个资源**：实时容器日志、统计信息和compose项目信息
- **类型安全**：完整的类型提示，配合Pydantic验证和mypy严格模式
- **安全控制**：三级安全系统(安全/中等/破坏性)，具有可配置的限制
- **全面测试**：88%以上的测试覆盖率，包含单元测试和集成测试
- **现代Python**：使用Python 3.11+、uv包管理器和async-first设计构建

## 快速开始

### 前置条件

- Python 3.11或更高版本
- 已安装并运行Docker
- [uv](https://github.com/astral-sh/uv)包管理器(推荐)或pip

### 安装

#### 选项1：使用uvx(推荐)

```bash
# 无需安装直接运行
uvx mcp-docker
```

#### 选项2：使用uv

```bash
# 从源码安装
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### 选项3：使用pip

```bash
# 从源码安装
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### 配置

服务器可以通过环境变量或`.env`文件进行配置。

#### 平台特定的Docker配置

**重要**：必须为您的平台正确设置`DOCKER_BASE_URL`：

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

#### 所有配置选项

```bash
# Docker配置
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (默认)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # API超时时间(秒) (默认: 60)
export DOCKER_TLS_VERIFY=false  # 启用TLS验证 (默认: false)
export DOCKER_TLS_CA_CERT="/path/to/ca.pem"  # CA证书路径 (可选)
export DOCKER_TLS_CLIENT_CERT="/path/to/cert.pem"  # 客户端证书路径 (可选)
export DOCKER_TLS_CLIENT_KEY="/path/to/key.pem"  # 客户端密钥路径 (可选)

# 安全配置
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # 允许rm、prune操作 (默认: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # 允许特权容器 (默认: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # 需要确认 (默认: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # 最大并发操作数 (默认: 10)

# 服务器配置
export MCP_SERVER_NAME="mcp-docker"  # MCP服务器名称 (默认: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # MCP服务器版本 (默认: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL (默认: INFO)
export MCP_DOCKER_LOG_PATH="/path/to/mcp_docker.log"  # 日志文件路径 (可选，默认为工作目录中的mcp_docker.log)
```

#### 使用.env文件

或者，在项目目录中创建`.env`文件：

```bash
# .env文件示例 (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# .env文件示例 (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Claude Desktop配置

添加到您的Claude Desktop配置：

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**基本配置(stdio传输 - 推荐):**

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

**Windows配置:**

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

### 高级用法

#### SSE传输(HTTP)

服务器除了默认的stdio传输外，还支持通过HTTP的SSE(服务器发送事件)传输：

```bash
# 使用SSE传输运行
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**命令行选项:**

- `--transport`: 传输类型(`stdio`或`sse`，默认: `stdio`)
- `--host`: SSE服务器绑定主机 (默认: `127.0.0.1`)
- `--port`: SSE服务器绑定端口 (默认: `8000`)

#### 自定义日志路径

使用环境变量`MCP_DOCKER_LOG_PATH`设置自定义日志文件位置：

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## 工具概览

服务器提供36个工具，分为6个类别：

### 容器管理(10个工具)

- `docker_list_containers` - 使用过滤器列出容器
- `docker_inspect_container` - 获取详细的容器信息
- `docker_create_container` - 创建新容器
- `docker_start_container` - 启动容器
- `docker_stop_container` - 优雅地停止容器
- `docker_restart_container` - 重启容器
- `docker_remove_container` - 删除容器
- `docker_container_logs` - 获取容器日志
- `docker_exec_command` - 在容器中执行命令
- `docker_container_stats` - 获取资源使用统计

### Docker Compose管理(12个工具)

- `docker_compose_up` - 启动compose项目服务
- `docker_compose_down` - 停止并删除compose服务
- `docker_compose_restart` - 重启compose服务
- `docker_compose_stop` - 停止compose服务
- `docker_compose_ps` - 列出compose项目服务
- `docker_compose_logs` - 获取compose服务日志
- `docker_compose_exec` - 在compose服务中执行命令
- `docker_compose_build` - 构建或重新构建compose服务
- `docker_compose_write_file` - 在compose_files/目录中创建compose文件
- `docker_compose_scale` - 扩展compose服务
- `docker_compose_validate` - 验证compose文件语法
- `docker_compose_config` - 获取已解析的compose配置

### 镜像管理(9个工具)

- `docker_list_images` - 列出镜像
- `docker_inspect_image` - 获取镜像详情
- `docker_pull_image` - 从仓库拉取
- `docker_build_image` - 从Dockerfile构建
- `docker_push_image` - 推送到仓库
- `docker_tag_image` - 标记镜像
- `docker_remove_image` - 删除镜像
- `docker_prune_images` - 清理未使用的镜像
- `docker_image_history` - 查看层历史

### 网络管理(6个工具)

- `docker_list_networks` - 列出网络
- `docker_inspect_network` - 获取网络详情
- `docker_create_network` - 创建网络
- `docker_connect_container` - 将容器连接到网络
- `docker_disconnect_container` - 从网络断开连接
- `docker_remove_network` - 删除网络

### 卷管理(5个工具)

- `docker_list_volumes` - 列出卷
- `docker_inspect_volume` - 获取卷详情
- `docker_create_volume` - 创建卷
- `docker_remove_volume` - 删除卷
- `docker_prune_volumes` - 清理未使用的卷

### 系统工具(6个工具)

- `docker_system_info` - 获取Docker系统信息
- `docker_system_df` - 磁盘使用统计
- `docker_system_prune` - 清理所有未使用的资源
- `docker_version` - 获取Docker版本信息
- `docker_events` - 流式传输Docker事件
- `docker_healthcheck` - 检查Docker守护进程健康状态

## 提示

五个提示帮助AI助手使用Docker：

- **troubleshoot_container** - 通过日志和配置分析诊断容器问题
- **optimize_container** - 获取资源使用和安全性的优化建议
- **generate_compose** - 从容器或描述生成docker-compose.yml
- **debug_networking** - 通过系统化L3-L7故障排除深入分析网络问题
- **security_audit** - 遵循CIS Docker Benchmark的全面安全分析和合规性映射

## 资源

五个资源提供对容器和compose数据的实时访问：

### 容器资源

- **container://logs/{container_id}** - 流式传输容器日志
- **container://stats/{container_id}** - 获取资源使用统计

### Compose资源

- **compose://config/{project_name}** - 获取已解析的compose项目配置
- **compose://services/{project_name}** - 列出compose项目中的服务
- **compose://logs/{project_name}/{service_name}** - 从compose服务获取日志

## Compose文件目录

`compose_files/`目录为创建和测试Docker Compose配置提供了一个安全的沙箱。

### 示例文件

包含三个即用型示例文件：

- `nginx-redis.yml` - 多服务Web堆栈(nginx + redis)
- `postgres-pgadmin.yml` - 带管理UI的数据库堆栈
- `simple-webapp.yml` - 最小单服务示例

### 创建自定义Compose文件

使用`docker_compose_write_file`工具创建自定义compose文件：

```python
# Claude可以这样创建compose文件:
{
  "filename": "my-stack",  # 将保存为user-my-stack.yml
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

### 安全功能

通过工具编写的所有compose文件：

- ✅ 仅限于`compose_files/`目录
- ✅ 自动添加`user-`前缀以区别于示例
- ✅ 验证YAML语法和结构
- ✅ 检查危险的卷挂载(/, /etc, /root等)
- ✅ 验证适当的端口范围和网络配置
- ✅ 防止路径遍历攻击

### 测试工作流

测试compose功能的推荐工作流：

1. **创建** 使用`docker_compose_write_file`创建compose文件
2. **验证** 使用`docker_compose_validate`验证
3. **启动** 使用`docker_compose_up`启动服务
4. **检查** 使用`docker_compose_ps`检查状态
5. **查看** 使用`docker_compose_logs`查看日志
6. **清理** 使用`docker_compose_down`清理

## 安全系统

服务器实现了三级安全系统：

1. **安全(SAFE)** - 只读操作(list、inspect、logs、stats)
   - 无限制
   - 始终允许

2. **中等(MODERATE)** - 状态更改但可逆(start、stop、create)
   - 可以修改系统状态
   - 通常安全

3. **破坏性(DESTRUCTIVE)** - 永久更改(remove、prune)
   - 需要`SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - 可能需要确认
   - 不能轻易撤销

## 文档

- [API参考](API.md) - 完整的工具文档和示例
- [设置指南](SETUP.md) - 安装和配置详情
- [使用示例](EXAMPLES.md) - 实用使用场景
- [架构](ARCHITECTURE.md) - 设计原则和实现

## 开发

### 设置开发环境

```bash
# 克隆仓库
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# 安装依赖
uv sync --group dev

# 运行测试
uv run pytest

# 运行代码检查
uv run ruff check src tests
uv run ruff format src tests

# 运行类型检查
uv run mypy src tests
```

### 运行测试

```bash
# 运行所有测试并生成覆盖率报告
uv run pytest --cov=mcp_docker --cov-report=html

# 仅运行单元测试
uv run pytest tests/unit/ -v

# 运行集成测试(需要Docker)
uv run pytest tests/integration/ -v -m integration
```

### 项目结构

```
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # 入口点
│       ├── server.py            # MCP服务器实现
│       ├── config.py            # 配置管理
│       ├── docker/              # Docker SDK包装器
│       ├── tools/               # MCP工具实现
│       ├── resources/           # MCP资源提供者
│       ├── prompts/             # MCP提示模板
│       └── utils/               # 实用工具(日志、验证、安全)
├── tests/                       # 测试套件
├── docs/                        # 文档
└── pyproject.toml              # 项目配置
```

## 要求

- **Python**: 3.11或更高版本
- **Docker**: 任何最新版本(已在20.10+上测试)
- **依赖项**:
  - `mcp>=1.2.0` - MCP SDK
  - `docker>=7.1.0` - Docker SDK for Python
  - `pydantic>=2.0.0` - 数据验证
  - `loguru>=0.7.0` - 日志记录

### 代码标准

- 遵循PEP 8风格指南
- 为所有函数使用类型提示
- 编写文档字符串(Google风格)
- 保持90%以上的测试覆盖率
- 通过所有代码检查和类型检查

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](../LICENSE)文件。

## 致谢

- 使用Anthropic的[模型上下文协议](https://modelcontextprotocol.io)构建
- 使用官方[Docker SDK for Python](https://docker-py.readthedocs.io/)
- 由现代Python工具驱动：[uv](https://github.com/astral-sh/uv)、[ruff](https://github.com/astral-sh/ruff)、[mypy](https://mypy-lang.org/)、[pytest](https://pytest.org/)

## 路线图

- [x] 完整的Docker Compose支持(11个工具、2个提示、3个资源)
- [ ] Docker Swarm操作
- [ ] 远程Docker主机支持
- [ ] 增强流式传输(构建/拉取进度)
- [ ] WebSocket传输选项
- [ ] Docker Scout集成
