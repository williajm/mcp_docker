# Serveur MCP Docker

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
[![Documentation en Anglais](https://img.shields.io/badge/docs-English-blue)](https://github.com/williajm/mcp_docker/blob/main/README.md)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

Un serveur [Model Context Protocol (MCP)](https://modelcontextprotocol.io) qui expose les fonctionnalités Docker aux assistants IA comme Claude. Gérez les conteneurs, images, réseaux et volumes via une API typée et documentée avec des contrôles de sécurité.

## Fonctionnalités

- **48 Outils Docker** : Gestion complète des conteneurs, images, réseaux, volumes, système et **Docker Compose**
- **5 Prompts IA** : Dépannage et optimisation intelligents pour les conteneurs et stacks compose
- **5 Ressources** : Logs en temps réel, statistiques des conteneurs et informations sur les projets compose
- **Sécurité des Types** : Annotations de type complètes avec validation Pydantic et mode strict mypy
- **Contrôles de Sécurité** : Système de sécurité à trois niveaux (sûr/modéré/destructif) avec restrictions configurables
- **Tests Complets** : Couverture de tests de 88%+ avec tests unitaires et d'intégration
- **Python Moderne** : Construit avec Python 3.11+, gestionnaire de paquets uv et conception async-first

## Démarrage Rapide

### Prérequis

- Python 3.11 ou supérieur
- Docker installé et en cours d'exécution
- Gestionnaire de paquets [uv](https://github.com/astral-sh/uv) (recommandé) ou pip

### Installation

#### Option 1 : Utilisation de uvx (Recommandé)

```bash
# Exécuter directement sans installation
uvx mcp-docker
```

#### Option 2 : Utilisation de uv

```bash
# Installer depuis les sources
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Option 3 : Utilisation de pip

```bash
# Installer depuis les sources
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Configuration

Le serveur peut être configuré via des variables d'environnement ou un fichier `.env`.

#### Configuration Docker Spécifique à la Plateforme

**IMPORTANT** : Le `DOCKER_BASE_URL` doit être correctement défini pour votre plateforme :

**Linux / macOS :**
```bash
export DOCKER_BASE_URL="unix:///var/run/docker.sock"
```

**Windows (Docker Desktop) :**
```cmd
set DOCKER_BASE_URL=npipe:////./pipe/docker_engine
```

**PowerShell :**
```powershell
$env:DOCKER_BASE_URL="npipe:////./pipe/docker_engine"
```

#### Toutes les Options de Configuration

```bash
# Configuration Docker
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (par défaut)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # Délai d'expiration de l'API en secondes (par défaut : 60)
export DOCKER_TLS_VERIFY=false  # Activer la vérification TLS (par défaut : false)
export DOCKER_TLS_CA_CERT="/chemin/vers/ca.pem"  # Chemin vers le certificat CA (optionnel)
export DOCKER_TLS_CLIENT_CERT="/chemin/vers/cert.pem"  # Chemin vers le certificat client (optionnel)
export DOCKER_TLS_CLIENT_KEY="/chemin/vers/key.pem"  # Chemin vers la clé client (optionnel)

# Configuration de Sécurité
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Autoriser les opérations rm, prune (par défaut : false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Autoriser les conteneurs privilégiés (par défaut : false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Exiger une confirmation (par défaut : true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Maximum d'opérations simultanées (par défaut : 10)

# Configuration Serveur
export MCP_SERVER_NAME="mcp-docker"  # Nom du serveur MCP (par défaut : mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # Version du serveur MCP (par défaut : 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Niveau de journalisation : DEBUG, INFO, WARNING, ERROR, CRITICAL (par défaut : INFO)
export MCP_DOCKER_LOG_PATH="/chemin/vers/mcp_docker.log"  # Chemin du fichier journal (optionnel, par défaut mcp_docker.log dans le répertoire de travail)
```

#### Utilisation d'un Fichier .env

Alternativement, créez un fichier `.env` dans votre répertoire de projet :

```bash
# Exemple de fichier .env (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# Exemple de fichier .env (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Configuration de Claude Desktop

Ajoutez à votre configuration Claude Desktop :
- macOS : `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows : `%APPDATA%\Claude\claude_desktop_config.json`
- Linux : `~/.config/Claude/claude_desktop_config.json`

**Configuration de base (transport stdio - recommandé) :**
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

**Configuration Windows :**
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

### Utilisation Avancée

#### Transport SSE (HTTP)

Le serveur prend en charge le transport SSE (Server-Sent Events) sur HTTP en plus du transport stdio par défaut :

```bash
# Exécuter avec le transport SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Options en ligne de commande :**
- `--transport` : Type de transport (`stdio` ou `sse`, par défaut : `stdio`)
- `--host` : Hôte pour lier le serveur SSE (par défaut : `127.0.0.1`)
- `--port` : Port pour lier le serveur SSE (par défaut : `8000`)

#### Chemin de Journal Personnalisé

Définissez un emplacement de fichier journal personnalisé en utilisant la variable d'environnement `MCP_DOCKER_LOG_PATH` :

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Vue d'Ensemble des Outils

Le serveur fournit 48 outils organisés en 6 catégories :

### Gestion des Conteneurs (10 outils)
- `docker_list_containers` - Lister les conteneurs avec filtres
- `docker_inspect_container` - Obtenir les informations détaillées du conteneur
- `docker_create_container` - Créer un nouveau conteneur
- `docker_start_container` - Démarrer le conteneur
- `docker_stop_container` - Arrêter le conteneur gracieusement
- `docker_restart_container` - Redémarrer le conteneur
- `docker_remove_container` - Supprimer le conteneur
- `docker_container_logs` - Obtenir les logs du conteneur
- `docker_exec_command` - Exécuter une commande dans le conteneur
- `docker_container_stats` - Obtenir les statistiques d'utilisation des ressources

### Gestion Docker Compose (12 outils)
- `docker_compose_up` - Démarrer les services du projet compose
- `docker_compose_down` - Arrêter et supprimer les services compose
- `docker_compose_restart` - Redémarrer les services compose
- `docker_compose_stop` - Arrêter les services compose
- `docker_compose_ps` - Lister les services du projet compose
- `docker_compose_logs` - Obtenir les logs des services compose
- `docker_compose_exec` - Exécuter une commande dans un service compose
- `docker_compose_build` - Construire ou reconstruire les services compose
- `docker_compose_write_file` - Créer des fichiers compose dans le répertoire compose_files/
- `docker_compose_scale` - Mettre à l'échelle les services compose
- `docker_compose_validate` - Valider la syntaxe du fichier compose
- `docker_compose_config` - Obtenir la configuration compose résolue

### Gestion des Images (9 outils)
- `docker_list_images` - Lister les images
- `docker_inspect_image` - Obtenir les détails de l'image
- `docker_pull_image` - Récupérer depuis le registre
- `docker_build_image` - Construire depuis un Dockerfile
- `docker_push_image` - Pousser vers le registre
- `docker_tag_image` - Étiqueter l'image
- `docker_remove_image` - Supprimer l'image
- `docker_prune_images` - Nettoyer les images inutilisées
- `docker_image_history` - Voir l'historique des couches

### Gestion des Réseaux (6 outils)
- `docker_list_networks` - Lister les réseaux
- `docker_inspect_network` - Obtenir les détails du réseau
- `docker_create_network` - Créer un réseau
- `docker_connect_container` - Connecter le conteneur au réseau
- `docker_disconnect_container` - Déconnecter du réseau
- `docker_remove_network` - Supprimer le réseau

### Gestion des Volumes (5 outils)
- `docker_list_volumes` - Lister les volumes
- `docker_inspect_volume` - Obtenir les détails du volume
- `docker_create_volume` - Créer un volume
- `docker_remove_volume` - Supprimer le volume
- `docker_prune_volumes` - Nettoyer les volumes inutilisés

### Outils Système (6 outils)
- `docker_system_info` - Obtenir les informations système Docker
- `docker_system_df` - Statistiques d'utilisation du disque
- `docker_system_prune` - Nettoyer toutes les ressources inutilisées
- `docker_version` - Obtenir les informations de version Docker
- `docker_events` - Diffuser les événements Docker
- `docker_healthcheck` - Vérifier l'état du daemon Docker

## Prompts

Cinq prompts aident les assistants IA à travailler avec Docker et Compose :

### Prompts Conteneurs
- **troubleshoot_container** - Diagnostiquer les problèmes de conteneur avec analyse des logs et de la configuration
- **optimize_container** - Obtenir des suggestions d'optimisation pour l'utilisation des ressources et la sécurité
- **generate_compose** - Générer docker-compose.yml à partir de conteneurs ou de descriptions

### Prompts Compose
- **troubleshoot_compose_stack** - Diagnostiquer les problèmes de projet Docker Compose et les dépendances de service
- **optimize_compose_config** - Optimiser la configuration compose pour les performances, la fiabilité et la sécurité

## Ressources

Cinq ressources fournissent un accès en temps réel aux données des conteneurs et compose :

### Ressources Conteneurs
- **container://logs/{container_id}** - Diffuser les logs du conteneur
- **container://stats/{container_id}** - Obtenir les statistiques d'utilisation des ressources

### Ressources Compose
- **compose://config/{project_name}** - Obtenir la configuration du projet compose résolue
- **compose://services/{project_name}** - Lister les services dans un projet compose
- **compose://logs/{project_name}/{service_name}** - Obtenir les logs d'un service compose

## Répertoire des Fichiers Compose

Le répertoire `compose_files/` fournit un bac à sable sécurisé pour créer et tester les configurations Docker Compose.

### Fichiers d'Exemple

Trois fichiers d'exemple prêts à l'emploi sont inclus :
- `nginx-redis.yml` - Stack web multi-services (nginx + redis)
- `postgres-pgadmin.yml` - Stack de base de données avec interface d'administration
- `simple-webapp.yml` - Exemple minimal à service unique

### Création de Fichiers Compose Personnalisés

Utilisez l'outil `docker_compose_write_file` pour créer des fichiers compose personnalisés :

```python
# Claude peut créer des fichiers compose comme ceci :
{
  "filename": "mon-stack",  # Sera enregistré sous user-mon-stack.yml
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

### Fonctionnalités de Sécurité

Tous les fichiers compose écrits via l'outil sont :
- ✅ Restreints au répertoire `compose_files/` uniquement
- ✅ Automatiquement préfixés par `user-` pour les distinguer des exemples
- ✅ Validés pour la syntaxe et la structure YAML
- ✅ Vérifiés pour les montages de volumes dangereux (/, /etc, /root, etc.)
- ✅ Validés pour les plages de ports et configurations réseau appropriées
- ✅ Protégés contre les attaques de traversée de chemin

### Workflow de Test

Workflow recommandé pour tester la fonctionnalité compose :

1. **Créer** un fichier compose avec `docker_compose_write_file`
2. **Valider** avec `docker_compose_validate`
3. **Démarrer** les services avec `docker_compose_up`
4. **Vérifier** l'état avec `docker_compose_ps`
5. **Voir** les logs avec `docker_compose_logs`
6. **Nettoyer** avec `docker_compose_down`

## Système de Sécurité

Le serveur implémente un système de sécurité à trois niveaux :

1. **SÛR (SAFE)** - Opérations en lecture seule (list, inspect, logs, stats)
   - Aucune restriction
   - Toujours autorisé

2. **MODÉRÉ (MODERATE)** - Changements d'état mais réversibles (start, stop, create)
   - Peut modifier l'état du système
   - Généralement sûr

3. **DESTRUCTIF (DESTRUCTIVE)** - Changements permanents (remove, prune)
   - Nécessite `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Peut nécessiter une confirmation
   - Ne peut pas être facilement annulé

## Documentation

- [Référence API](API.md) - Documentation complète des outils avec exemples
- [Guide de Configuration](SETUP.md) - Détails d'installation et de configuration
- [Exemples d'Utilisation](EXAMPLES.md) - Scénarios d'utilisation pratiques
- [Architecture](ARCHITECTURE.md) - Principes de conception et implémentation

## Développement

### Configurer l'Environnement de Développement

```bash
# Cloner le dépôt
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Installer les dépendances
uv sync --group dev

# Exécuter les tests
uv run pytest

# Exécuter le linting
uv run ruff check src tests
uv run ruff format src tests

# Exécuter la vérification de type
uv run mypy src tests
```

### Exécution des Tests

```bash
# Exécuter tous les tests avec couverture
uv run pytest --cov=mcp_docker --cov-report=html

# Exécuter uniquement les tests unitaires
uv run pytest tests/unit/ -v

# Exécuter les tests d'intégration (nécessite Docker)
uv run pytest tests/integration/ -v -m integration
```

### Structure du Projet

```
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Point d'entrée
│       ├── server.py            # Implémentation du serveur MCP
│       ├── config.py            # Gestion de la configuration
│       ├── docker/              # Wrapper Docker SDK
│       ├── tools/               # Implémentations des outils MCP
│       ├── resources/           # Fournisseurs de ressources MCP
│       ├── prompts/             # Modèles de prompts MCP
│       └── utils/               # Utilitaires (journalisation, validation, sécurité)
├── tests/                       # Suite de tests
├── docs/                        # Documentation
└── pyproject.toml              # Configuration du projet
```

## Exigences

- **Python** : 3.11 ou supérieur
- **Docker** : Toute version récente (testé avec 20.10+)
- **Dépendances** :
  - `mcp>=1.2.0` - SDK MCP
  - `docker>=7.1.0` - SDK Docker pour Python
  - `pydantic>=2.0.0` - Validation des données
  - `loguru>=0.7.0` - Journalisation

### Normes de Code

- Suivre les directives de style PEP 8
- Utiliser les annotations de type pour toutes les fonctions
- Écrire des docstrings (style Google)
- Maintenir une couverture de tests de 90%+
- Réussir tous les linting et vérifications de type

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](../LICENSE) pour plus de détails.

## Remerciements

- Construit avec le [Model Context Protocol](https://modelcontextprotocol.io) d'Anthropic
- Utilise le [Docker SDK officiel pour Python](https://docker-py.readthedocs.io/)
- Propulsé par les outils Python modernes : [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Feuille de Route

- [x] Support complet de Docker Compose (11 outils, 2 prompts, 3 ressources)
- [ ] Opérations Docker Swarm
- [ ] Support d'hôte Docker distant
- [ ] Streaming amélioré (progression build/pull)
- [ ] Option de transport WebSocket
- [ ] Intégration Docker Scout
