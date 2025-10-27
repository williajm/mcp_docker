# MCP Docker サーバー

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml)
[![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml)
[![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml)
[![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml)
[![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![Python 3.11-3.13](https://img.shields.io/badge/python-3.11--3.13-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://williajm.github.io/mcp_docker/)
[![Documentation in English](https://img.shields.io/badge/docs-English-blue)](https://github.com/williajm/mcp_docker/blob/main/README.md)
[![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.fr.md)
[![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.de.md)
[![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.it.md)
[![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.es.md)
[![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.uk.md)
[![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.pt.md)
[![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.zh.md)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

ClaudeのようなAIアシスタントにDocker機能を提供する[Model Context Protocol (MCP)](https://modelcontextprotocol.io)サーバー。セキュリティコントロール付きの型安全で文書化されたAPIを通じて、コンテナ、イメージ、ネットワーク、ボリュームを管理します。

## 機能

- **48のDockerツール**: コンテナ、イメージ、ネットワーク、ボリューム、システム、**Docker Compose**の完全な管理
- **5つのAIプロンプト**: コンテナとcomposeスタックのインテリジェントなトラブルシューティングと最適化
- **5つのリソース**: リアルタイムのコンテナログ、統計、composeプロジェクト情報
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

サーバーは6つのカテゴリに整理された48のツールを提供します:

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

### Docker Compose管理(12ツール)
- `docker_compose_up` - composeプロジェクトのサービスを起動
- `docker_compose_down` - composeサービスを停止して削除
- `docker_compose_restart` - composeサービスを再起動
- `docker_compose_stop` - composeサービスを停止
- `docker_compose_ps` - composeプロジェクトのサービスをリスト
- `docker_compose_logs` - composeサービスのログを取得
- `docker_compose_exec` - composeサービス内でコマンドを実行
- `docker_compose_build` - composeサービスをビルドまたは再ビルド
- `docker_compose_write_file` - compose_files/ディレクトリにcomposeファイルを作成
- `docker_compose_scale` - composeサービスをスケール
- `docker_compose_validate` - composeファイルの構文を検証
- `docker_compose_config` - 解決されたcompose設定を取得

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

5つのプロンプトがAIアシスタントのDockerとComposeの作業を支援します:

### コンテナプロンプト
- **troubleshoot_container** - ログと設定分析によるコンテナ問題の診断
- **optimize_container** - リソース使用とセキュリティの最適化提案を取得
- **generate_compose** - コンテナまたは説明からdocker-compose.ymlを生成

### Composeプロンプト
- **troubleshoot_compose_stack** - Docker Composeプロジェクトの問題とサービス依存関係を診断
- **optimize_compose_config** - パフォーマンス、信頼性、セキュリティのためにcompose設定を最適化

## リソース

5つのリソースがコンテナとcomposeデータへのリアルタイムアクセスを提供します:

### コンテナリソース
- **container://logs/{container_id}** - コンテナログをストリーム
- **container://stats/{container_id}** - リソース使用統計を取得

### Composeリソース
- **compose://config/{project_name}** - 解決されたcomposeプロジェクト設定を取得
- **compose://services/{project_name}** - composeプロジェクト内のサービスをリスト
- **compose://logs/{project_name}/{service_name}** - composeサービスからログを取得

## Composeファイルディレクトリ

`compose_files/`ディレクトリは、Docker Compose設定を作成およびテストするための安全なサンドボックスを提供します。

### サンプルファイル

3つのすぐに使えるサンプルファイルが含まれています:
- `nginx-redis.yml` - マルチサービスWebスタック(nginx + redis)
- `postgres-pgadmin.yml` - 管理UIを持つデータベーススタック
- `simple-webapp.yml` - 最小限のシングルサービスの例

### カスタムComposeファイルの作成

`docker_compose_write_file`ツールを使用してカスタムcomposeファイルを作成:

```python
# Claudeはこのようにcomposeファイルを作成できます:
{
  "filename": "my-stack",  # user-my-stack.ymlとして保存されます
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

### セキュリティ機能

ツールを通じて書き込まれたすべてのcomposeファイルは:
- ✅ `compose_files/`ディレクトリのみに制限
- ✅ サンプルと区別するために自動的に`user-`が付加
- ✅ YAML構文と構造を検証
- ✅ 危険なボリュームマウント(/, /etc, /root など)をチェック
- ✅ 適切なポート範囲とネットワーク設定を検証
- ✅ パストラバーサル攻撃から保護

### テストワークフロー

compose機能をテストするための推奨ワークフロー:

1. **作成** `docker_compose_write_file`を使用してcomposeファイルを作成
2. **検証** `docker_compose_validate`で検証
3. **起動** `docker_compose_up`でサービスを起動
4. **確認** `docker_compose_ps`でステータスを確認
5. **表示** `docker_compose_logs`でログを表示
6. **クリーンアップ** `docker_compose_down`でクリーンアップ

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

```
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

## ロードマップ

- [x] Docker Composeの完全サポート(11ツール、2プロンプト、3リソース)
- [ ] Docker Swarm操作
- [ ] リモートDockerホストサポート
- [ ] 拡張ストリーミング(ビルド/プル進捗)
- [ ] WebSocketトランスポートオプション
- [ ] Docker Scout統合
