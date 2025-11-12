# MCP Docker サーバー

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

## 機能

- **36のDockerツール**: コンテナ、イメージ、ネットワーク、ボリューム、システムの完全な管理
- **5つのAIプロンプト**: インテリジェントなトラブルシューティング、最適化、ネットワークデバッグ、セキュリティ分析
- **2つのリソース**: リアルタイムのコンテナログとリソース統計
- **型安全性**: Pydantic検証とmypyの厳密モードによる完全な型ヒント
- **セキュリティコントロール**: 設定可能な制限を持つ3段階のセキュリティシステム(安全/中程度/破壊的)
- **包括的なテスト**: ユニットテストと統合テストによる88%以上のテストカバレッジ
- **モダンなPython**: Python 3.11+、uvパッケージマネージャー、async-firstデザインで構築

## クイックスタート

### 前提条件

- Python 3.11以上
- Dockerがインストールされ実行中
- [uv](https://github.com/astral-sh/uv)パッケージマネージャー(推奨)またはpip

### インストール

#### オプション1: uvxを使用(推奨)

```bash
# インストールせずに直接実行
uvx mcp-docker
```

#### オプション2: uvを使用

```bash
# ソースからインストール
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### オプション3: pipを使用

```bash
# ソースからインストール
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### 設定

サーバーは環境変数または`.env`ファイルで設定できます。

#### プラットフォーム固有のDocker設定

**重要**: プラットフォームに合わせて`DOCKER_BASE_URL`を正しく設定する必要があります:

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

#### すべての設定オプション

```bash
# Docker設定
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (デフォルト)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # APIタイムアウト(秒) (デフォルト: 60)
export DOCKER_TLS_VERIFY=false  # TLS検証を有効化 (デフォルト: false)
export DOCKER_TLS_CA_CERT="/path/to/ca.pem"  # CA証明書へのパス (オプション)
export DOCKER_TLS_CLIENT_CERT="/path/to/cert.pem"  # クライアント証明書へのパス (オプション)
export DOCKER_TLS_CLIENT_KEY="/path/to/key.pem"  # クライアント鍵へのパス (オプション)

# セキュリティ設定
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # rm、prune操作を許可 (デフォルト: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # 特権コンテナを許可 (デフォルト: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # 確認を要求 (デフォルト: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # 最大同時操作数 (デフォルト: 10)

# サーバー設定
export MCP_SERVER_NAME="mcp-docker"  # MCPサーバー名 (デフォルト: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # MCPサーバーバージョン (デフォルト: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # ログレベル: DEBUG, INFO, WARNING, ERROR, CRITICAL (デフォルト: INFO)
export MCP_DOCKER_LOG_PATH="/path/to/mcp_docker.log"  # ログファイルパス (オプション、デフォルトは作業ディレクトリのmcp_docker.log)
```

#### .envファイルを使用

代わりに、プロジェクトディレクトリに`.env`ファイルを作成します:

```bash
# .envファイルの例 (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# .envファイルの例 (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Claude Desktopの設定

Claude Desktop設定に追加:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**基本設定(stdioトランスポート - 推奨):**

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

**Windows設定:**

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

### 高度な使用方法

#### SSEトランスポート(HTTP)

サーバーはデフォルトのstdioトランスポートに加えて、HTTP上のSSE(Server-Sent Events)トランスポートをサポートしています:

```bash
# SSEトランスポートで実行
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**コマンドラインオプション:**

- `--transport`: トランスポートタイプ(`stdio`または`sse`、デフォルト: `stdio`)
- `--host`: SSEサーバーのバインドホスト (デフォルト: `127.0.0.1`)
- `--port`: SSEサーバーのバインドポート (デフォルト: `8000`)

#### カスタムログパス

環境変数`MCP_DOCKER_LOG_PATH`を使用してカスタムログファイルの場所を設定:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## ツール概要

サーバーは5つのカテゴリに整理された36のツールを提供します:

### コンテナ管理(10ツール)

- `docker_list_containers` - フィルター付きでコンテナをリスト
- `docker_inspect_container` - 詳細なコンテナ情報を取得
- `docker_create_container` - 新しいコンテナを作成
- `docker_start_container` - コンテナを起動
- `docker_stop_container` - コンテナを正常に停止
- `docker_restart_container` - コンテナを再起動
- `docker_remove_container` - コンテナを削除
- `docker_container_logs` - コンテナログを取得
- `docker_exec_command` - コンテナ内でコマンドを実行
- `docker_container_stats` - リソース使用統計を取得

### イメージ管理(9ツール)

- `docker_list_images` - イメージをリスト
- `docker_inspect_image` - イメージの詳細を取得
- `docker_pull_image` - レジストリからプル
- `docker_build_image` - Dockerfileからビルド
- `docker_push_image` - レジストリにプッシュ
- `docker_tag_image` - イメージにタグ付け
- `docker_remove_image` - イメージを削除
- `docker_prune_images` - 未使用のイメージをクリーンアップ
- `docker_image_history` - レイヤー履歴を表示

### ネットワーク管理(6ツール)

- `docker_list_networks` - ネットワークをリスト
- `docker_inspect_network` - ネットワークの詳細を取得
- `docker_create_network` - ネットワークを作成
- `docker_connect_container` - コンテナをネットワークに接続
- `docker_disconnect_container` - ネットワークから切断
- `docker_remove_network` - ネットワークを削除

### ボリューム管理(5ツール)

- `docker_list_volumes` - ボリュームをリスト
- `docker_inspect_volume` - ボリュームの詳細を取得
- `docker_create_volume` - ボリュームを作成
- `docker_remove_volume` - ボリュームを削除
- `docker_prune_volumes` - 未使用のボリュームをクリーンアップ

### システムツール(6ツール)

- `docker_system_info` - Dockerシステム情報を取得
- `docker_system_df` - ディスク使用統計
- `docker_system_prune` - すべての未使用リソースをクリーンアップ
- `docker_version` - Dockerバージョン情報を取得
- `docker_events` - Dockerイベントをストリーム
- `docker_healthcheck` - Dockerデーモンの健全性をチェック

## プロンプト

5つのプロンプトがAIアシスタントのDockerの作業を支援します:

- **troubleshoot_container** - ログと設定分析によるコンテナ問題の診断
- **optimize_container** - リソース使用とセキュリティの最適化提案を取得
- **generate_compose** - コンテナまたは説明からdocker-compose.ymlを生成
- **debug_networking** - L3-L7の体系的なトラブルシューティングによるネットワーク問題の詳細分析
- **security_audit** - CIS Docker Benchmarkに従ったコンプライアンスマッピング付きの包括的なセキュリティ分析

## リソース

2つのリソースがコンテナデータへのリアルタイムアクセスを提供します:

- **container://logs/{container_id}** - コンテナログをストリーム
- **container://stats/{container_id}** - リソース使用統計を取得

## セキュリティシステム

サーバーは3段階のセキュリティシステムを実装しています:

1. **安全(SAFE)** - 読み取り専用操作(list、inspect、logs、stats)
   - 制限なし
   - 常に許可

2. **中程度(MODERATE)** - 状態変更だが可逆的(start、stop、create)
   - システム状態を変更可能
   - 一般的に安全

3. **破壊的(DESTRUCTIVE)** - 永続的な変更(remove、prune)
   - `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`が必要
   - 確認が必要な場合あり
   - 簡単には元に戻せない

## ドキュメント

- [APIリファレンス](API.md) - 例付きの完全なツールドキュメント
- [セットアップガイド](SETUP.md) - インストールと設定の詳細
- [使用例](EXAMPLES.md) - 実用的な使用シナリオ
- [アーキテクチャ](ARCHITECTURE.md) - 設計原則と実装

## 開発

### 開発環境のセットアップ

```bash
# リポジトリをクローン
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# 依存関係をインストール
uv sync --group dev

# テストを実行
uv run pytest

# リンティングを実行
uv run ruff check src tests
uv run ruff format src tests

# 型チェックを実行
uv run mypy src tests
```

### テストの実行

```bash
# カバレッジ付きですべてのテストを実行
uv run pytest --cov=mcp_docker --cov-report=html

# ユニットテストのみを実行
uv run pytest tests/unit/ -v

# 統合テストを実行(Dockerが必要)
uv run pytest tests/integration/ -v -m integration
```

### プロジェクト構造

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # エントリーポイント
│       ├── server.py            # MCPサーバー実装
│       ├── config.py            # 設定管理
│       ├── docker/              # Docker SDKラッパー
│       ├── tools/               # MCPツール実装
│       ├── resources/           # MCPリソースプロバイダー
│       ├── prompts/             # MCPプロンプトテンプレート
│       └── utils/               # ユーティリティ(ロギング、検証、セキュリティ)
├── tests/                       # テストスイート
├── docs/                        # ドキュメント
└── pyproject.toml              # プロジェクト設定
```

## 要件

- **Python**: 3.11以上
- **Docker**: 最近のバージョン(20.10+でテスト済み)
- **依存関係**:
  - `mcp>=1.2.0` - MCP SDK
  - `docker>=7.1.0` - Docker SDK for Python
  - `pydantic>=2.0.0` - データ検証
  - `loguru>=0.7.0` - ロギング

### コード基準

- PEP 8スタイルガイドラインに従う
- すべての関数に型ヒントを使用
- docstringを記述(Googleスタイル)
- 90%以上のテストカバレッジを維持
- すべてのリンティングと型チェックに合格

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細は[LICENSE](../LICENSE)ファイルを参照してください。

## 謝辞

- Anthropicによる[Model Context Protocol](https://modelcontextprotocol.io)で構築
- 公式の[Docker SDK for Python](https://docker-py.readthedocs.io/)を使用
- モダンなPythonツールで駆動: [uv](https://github.com/astral-sh/uv)、[ruff](https://github.com/astral-sh/ruff)、[mypy](https://mypy-lang.org/)、[pytest](https://pytest.org/)
