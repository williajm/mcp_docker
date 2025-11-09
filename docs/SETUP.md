---
layout: default
title: Setup Guide
---

# Setup and Installation Guide

Complete guide for installing and configuring the MCP Docker server.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Options](#installation-options)
- [Claude Desktop Configuration](#claude-desktop-configuration)
- [Environment Variables](#environment-variables)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Platform-Specific Notes](#platform-specific-notes)
- [Uninstallation](#uninstallation)

## Prerequisites

### System Requirements

Before installing the MCP Docker server, ensure your system meets these requirements:

#### Required Software

1. **Python 3.11 or Higher**
   - Check your Python version:

     ```bash
     python --version
     # or
     python3 --version
     ```

   - If you need to install or upgrade Python:
     - **macOS**: Use Homebrew: `brew install python@3.11`
     - **Windows**: Download from [python.org](https://www.python.org/downloads/)
     - **Linux**: Use your package manager: `sudo apt install python3.11` (Ubuntu/Debian)

2. **Docker Engine**
   - Docker must be installed and running
   - Minimum version: Docker 20.10+ (tested with 20.10+)
   - Check Docker installation:

     ```bash
     docker --version
     docker ps
     ```

   - Install Docker:
     - **macOS**: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
     - **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
     - **Linux**: [Docker Engine for Linux](https://docs.docker.com/engine/install/)

3. **Package Manager** (recommended)
   - **uv** (recommended): Fast Python package manager

     ```bash
     # Install uv
     curl -LsSf https://astral.sh/uv/install.sh | sh
     # or on Windows (PowerShell)
     irm https://astral.sh/uv/install.ps1 | iex
     ```

   - **pip**: Comes with Python, fallback option

#### Hardware Requirements

- **CPU**: Any modern processor (x86_64 or ARM64)
- **RAM**: 512MB minimum (for the server itself)
- **Disk**: 100MB for installation
- **Network**: Internet connection for installation and pulling Docker images

#### Permissions

- **Docker Socket Access**: User must have permission to access the Docker daemon
  - **macOS/Windows**: Granted by Docker Desktop
  - **Linux**: Add user to `docker` group:

    ```bash
    sudo usermod -aG docker $USER
    # Log out and back in for changes to take effect
    ```

#### Platform-Specific Docker Configuration

**CRITICAL**: You must configure the correct Docker socket URL for your platform:

- **Linux/macOS**: `unix:///var/run/docker.sock` (default)
- **Windows**: `npipe:////./pipe/docker_engine` (Docker Desktop)

See [Environment Variables](#environment-variables) section for configuration details.

## Installation Options

Choose the installation method that best fits your workflow:

### Option 1: Using uvx (Recommended)

The fastest and easiest method - no installation required, runs directly:

```bash
# Run the server directly (downloads and caches automatically)
uvx mcp-docker

# Run with specific Python version
uvx --python 3.11 mcp-docker

# Run with environment variables
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true uvx mcp-docker
```

**Advantages:**

- No installation or setup required
- Automatically manages dependencies
- Isolates the server in its own environment
- Easy to update (just run again to get latest version)

**Best for:** Quick testing, Claude Desktop integration, minimal setup

### Option 2: Using uv (Development/Local)

Install from source for development or customization:

```bash
# Clone the repository
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Create virtual environment and install dependencies
uv sync

# Run the server
uv run mcp-docker

# Or activate the virtual environment
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
mcp-docker
```

**Advantages:**

- Full access to source code
- Easy to modify and test changes
- Includes development dependencies
- Better for contributors

**Best for:** Development, customization, contributing

### Option 3: Using pip

Traditional Python package installation:

```bash
# Install from source
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Create and activate virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Install the package
pip install -e .

# Run the server
mcp-docker
```

**Advantages:**

- Works with any Python environment
- Familiar to all Python developers
- No new tools to learn

**Best for:** Traditional Python workflows, integration with existing projects

### Option 4: From PyPI (Coming Soon)

Once published to PyPI, the simplest installation:

```bash
# Install globally (not recommended)
pip install mcp-docker

# Or in a virtual environment (recommended)
python -m venv mcp-env
source mcp-env/bin/activate
pip install mcp-docker

# Run the server
mcp-docker
```

## Claude Desktop Configuration

Configure Claude Desktop to use the MCP Docker server.

### Configuration File Location

The Claude Desktop configuration file is located at:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Basic Configuration

#### Using uvx (Recommended)

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"]
    }
  }
}
```

#### Using uv from Source

If you cloned the repository:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/mcp_docker", "run", "mcp-docker"]
    }
  }
}
```

Replace `/absolute/path/to/mcp_docker` with the actual path to your cloned repository.

#### Using pip Installation

If you installed with pip in a virtual environment:

```json
{
  "mcpServers": {
    "docker": {
      "command": "/absolute/path/to/.venv/bin/mcp-docker"
    }
  }
}
```

### Configuration with Environment Variables

Add environment variables to customize behavior:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_TIMEOUT": "60",
        "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "false",
        "SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE": "true",
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Platform-Specific Configuration

#### macOS

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

#### Windows

For Docker Desktop on Windows:

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

#### Linux

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

### Advanced Configuration Examples

#### Remote Docker Host

Connect to a remote Docker daemon over TCP:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "tcp://192.168.1.100:2375"
      }
    }
  }
}
```

#### Docker with TLS

Connect to a TLS-secured Docker daemon:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "tcp://192.168.1.100:2376",
        "DOCKER_TLS_VERIFY": "true",
        "DOCKER_TLS_CA_CERT": "/path/to/ca.pem",
        "DOCKER_TLS_CLIENT_CERT": "/path/to/cert.pem",
        "DOCKER_TLS_CLIENT_KEY": "/path/to/key.pem"
      }
    }
  }
}
```

#### Maximum Safety Mode

Most restrictive settings (read-only operations only):

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "false",
        "SAFETY_ALLOW_PRIVILEGED_CONTAINERS": "false",
        "SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE": "true",
        "SAFETY_MAX_CONCURRENT_OPERATIONS": "5"
      }
    }
  }
}
```

#### Development Mode

More permissive settings for development:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "true",
        "SAFETY_ALLOW_PRIVILEGED_CONTAINERS": "true",
        "SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE": "false",
        "MCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

## Environment Variables

Complete reference for all configuration options.

### Docker Configuration

Control how the server connects to Docker:

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_BASE_URL` | `unix:///var/run/docker.sock` | **PLATFORM-SPECIFIC**: Docker daemon socket URL. See platform examples below. |
| `DOCKER_TIMEOUT` | `60` | Timeout for Docker API operations in seconds. Increase for slow networks or large operations |
| `DOCKER_TLS_VERIFY` | `false` | Enable TLS verification for Docker daemon connection |
| `DOCKER_TLS_CA_CERT` | - | Path to CA certificate file for TLS verification |
| `DOCKER_TLS_CLIENT_CERT` | - | Path to client certificate file for TLS authentication |
| `DOCKER_TLS_CLIENT_KEY` | - | Path to client private key file for TLS authentication |

#### Platform-Specific DOCKER_BASE_URL Examples

**IMPORTANT**: The default value (`unix:///var/run/docker.sock`) only works on Linux/macOS. You **MUST** set the correct value for your platform.

**Linux:**

```bash
export DOCKER_BASE_URL="unix:///var/run/docker.sock"
```

**macOS:**

```bash
export DOCKER_BASE_URL="unix:///var/run/docker.sock"
```

**Windows (CMD):**

```cmd
set DOCKER_BASE_URL=npipe:////./pipe/docker_engine
```

**Windows (PowerShell):**

```powershell
$env:DOCKER_BASE_URL="npipe:////./pipe/docker_engine"
```

#### Other Configuration Examples

**Remote Docker over TCP:**

```bash
export DOCKER_BASE_URL="tcp://192.168.1.100:2375"
```

**Remote Docker with TLS:**

```bash
export DOCKER_BASE_URL="tcp://192.168.1.100:2376"
export DOCKER_TLS_VERIFY="true"
export DOCKER_TLS_CA_CERT="/path/to/ca.pem"
export DOCKER_TLS_CLIENT_CERT="/path/to/cert.pem"
export DOCKER_TLS_CLIENT_KEY="/path/to/key.pem"
```

**Increase timeout for slow operations:**

```bash
export DOCKER_TIMEOUT="120"
```

### Safety Configuration

Control what operations are allowed:

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS` | `false` | Allow destructive operations (remove, prune). **Warning:** Set to `true` with caution! |
| `SAFETY_ALLOW_PRIVILEGED_CONTAINERS` | `false` | Allow creating privileged containers that can access host resources |
| `SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE` | `true` | Require explicit confirmation before destructive operations |
| `SAFETY_MAX_CONCURRENT_OPERATIONS` | `10` | Maximum number of concurrent Docker operations (1-100) |

**Safety Levels:**

1. **SAFE** - Read-only operations (list, inspect, logs, stats)
   - Always allowed
   - No risk of data loss
   - Examples: `docker_list_containers`, `docker_inspect_image`

2. **MODERATE** - State-changing but reversible (start, stop, create)
   - Allowed by default
   - Can be undone
   - Examples: `docker_start_container`, `docker_create_network`

3. **DESTRUCTIVE** - Permanent changes (remove, prune)
   - Requires `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Cannot be easily undone
   - Examples: `docker_remove_container`, `docker_prune_volumes`

**Examples:**

```bash
# Maximum safety (production)
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="false"
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS="false"
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE="true"

# Development mode
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="true"
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS="true"
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE="false"

# Limit concurrent operations
export SAFETY_MAX_CONCURRENT_OPERATIONS="5"
```

### Server Configuration

Configure logging and server metadata:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVER_NAME` | `mcp-docker` | Name of the MCP server instance |
| `MCP_SERVER_VERSION` | `0.1.0` | Server version string |
| `MCP_LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `MCP_LOG_FORMAT` | (see below) | Custom log format string for loguru |

**Default Log Format:**

```
<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>
```

**Examples:**

```bash
# Debug logging for troubleshooting
export MCP_LOG_LEVEL="DEBUG"

# Minimal logging for production
export MCP_LOG_LEVEL="WARNING"

# Custom server name
export MCP_SERVER_NAME="my-docker-server"
```

### Using .env File

Instead of exporting variables, create a `.env` file in the project directory:

```bash
# .env file
DOCKER_BASE_URL=unix:///var/run/docker.sock
DOCKER_TIMEOUT=60

SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false

MCP_LOG_LEVEL=INFO
```

The server will automatically load these variables on startup.

## Verification

Verify that your installation is working correctly.

### Step 1: Test Docker Connection

First, ensure Docker is running and accessible:

```bash
# Check Docker is running
docker ps

# Check Docker socket permissions (Linux/macOS)
ls -la /var/run/docker.sock

# Test Docker info
docker info
```

### Step 2: Test Server Standalone

Run the server directly to check for errors:

```bash
# Using uvx
uvx mcp-docker

# Using uv
cd /path/to/mcp_docker
uv run mcp-docker

# Using pip
mcp-docker
```

The server should start without errors. You'll see log output similar to:

```
2025-10-24 10:30:15 | INFO     | mcp_docker.server:main:45 - Starting MCP Docker server
2025-10-24 10:30:15 | INFO     | mcp_docker.server:main:48 - Docker client initialized successfully
```

Press `Ctrl+C` to stop the server.

### Step 3: Test with Claude Desktop

1. Add the server configuration to Claude Desktop (see [Claude Desktop Configuration](#claude-desktop-configuration))

2. Restart Claude Desktop completely:
   - **macOS**: Quit Claude (Cmd+Q) and restart
   - **Windows**: Exit Claude from system tray and restart
   - **Linux**: Kill the process and restart

3. Open Claude and check the server status:
   - Look for the hammer icon (🔨) in the bottom-right
   - The Docker server should appear in the list
   - Status should show "Connected" or "Running"

4. Test with a simple query:

   ```
   List all Docker containers
   ```

   Claude should respond with a list of containers or confirm that no containers exist.

### Step 4: Run Test Commands

Try these commands in Claude to verify functionality:

1. **Check Docker version:**

   ```
   What version of Docker am I running?
   ```

2. **List images:**

   ```
   Show me all Docker images on my system
   ```

3. **System information:**

   ```
   Get Docker system information
   ```

4. **Test a safe operation:**

   ```
   Create a simple nginx container named test-container
   ```

5. **Test logs (if container exists):**

   ```
   Show me the logs for the test-container
   ```

### Verification Checklist

- [ ] Python 3.11+ is installed
- [ ] Docker is installed and running
- [ ] Docker socket is accessible
- [ ] Server starts without errors
- [ ] Claude Desktop shows server as connected
- [ ] Can list containers through Claude
- [ ] Can execute Docker commands through Claude

## Troubleshooting

Common issues and their solutions.

### Docker Daemon Not Running

**Symptoms:**

- Error: `Cannot connect to the Docker daemon`
- Error: `Error response from daemon`
- Server fails to start with connection errors

**Solutions:**

1. **Check if Docker is running:**

   ```bash
   docker ps
   ```

2. **Start Docker:**
   - **macOS**: Open Docker Desktop application
   - **Windows**: Start Docker Desktop from Start Menu
   - **Linux**:

     ```bash
     sudo systemctl start docker
     # or
     sudo service docker start
     ```

3. **Verify Docker socket exists:**

   ```bash
   # macOS/Linux
   ls -la /var/run/docker.sock

   # Windows (PowerShell)
   Test-Path \\.\pipe\docker_engine
   ```

4. **Check Docker Desktop settings:**
   - Ensure "Use the Docker Compose CLI" is enabled
   - Check that "Enable default Docker socket" is on

### Permission Errors

**Symptoms:**

- Error: `Permission denied while trying to connect to the Docker daemon socket`
- Error: `dial unix /var/run/docker.sock: connect: permission denied`

**Solutions:**

**Linux:**

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker

# Verify permissions
ls -la /var/run/docker.sock

# If needed, fix socket permissions
sudo chmod 666 /var/run/docker.sock
```

**macOS/Windows:**

- Docker Desktop should handle permissions automatically
- Try restarting Docker Desktop
- Reinstall Docker Desktop if issues persist

**Claude Desktop specific:**

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

### Python Version Issues

**Symptoms:**

- Error: `Python 3.11 or higher is required`
- Error: `SyntaxError` with modern Python syntax
- Server fails to install or import

**Solutions:**

1. **Check Python version:**

   ```bash
   python --version
   python3 --version
   python3.11 --version
   ```

2. **Install Python 3.11+:**

   ```bash
   # macOS
   brew install python@3.11

   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3.11 python3.11-venv

   # Windows
   # Download from python.org
   ```

3. **Use specific Python version with uvx:**

   ```bash
   uvx --python 3.11 mcp-docker
   ```

4. **Use specific Python version with uv:**

   ```bash
   uv venv --python 3.11
   ```

5. **Update Claude Desktop config to use specific Python:**

   ```json
   {
     "mcpServers": {
       "docker": {
         "command": "uvx",
         "args": ["--python", "3.11", "mcp-docker"]
       }
     }
   }
   ```

### Connection Issues

**Symptoms:**

- Server starts but Claude shows "Disconnected"
- Timeout errors
- Intermittent connection drops

**Solutions:**

1. **Increase timeout:**

   ```json
   {
     "mcpServers": {
       "docker": {
         "command": "uvx",
         "args": ["mcp-docker"],
         "env": {
           "DOCKER_TIMEOUT": "120"
         }
       }
     }
   }
   ```

2. **Check Claude Desktop logs:**
   - **macOS**: `~/Library/Logs/Claude/`
   - **Windows**: `%APPDATA%\Claude\logs\`
   - **Linux**: `~/.config/Claude/logs/`

3. **Test server manually:**

   ```bash
   MCP_LOG_LEVEL=DEBUG uvx mcp-docker
   ```

4. **Restart both server and Claude:**
   - Completely quit Claude (not just close window)
   - Restart Claude Desktop
   - Server will restart automatically

5. **Check for port conflicts:**

   ```bash
   # If using TCP
   netstat -an | grep 2375
   ```

### Platform-Specific Problems

#### macOS Issues

**Docker Desktop not starting:**

```bash
# Reset Docker Desktop
rm -rf ~/Library/Group\ Containers/group.com.docker
rm -rf ~/Library/Containers/com.docker.docker
# Reinstall Docker Desktop
```

**Permission issues with socket:**

```bash
# Check socket location
ls -la /var/run/docker.sock

# Should show: srw-rw---- 1 root docker
```

**Rosetta 2 on Apple Silicon:**

```bash
# If using x86_64 Docker on ARM Mac
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

#### Windows Issues

**Named pipe connection:**

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

**WSL2 Docker:**

```bash
# Inside WSL2
export DOCKER_HOST=unix:///var/run/docker.sock

# Or connect to Windows Docker from WSL2
export DOCKER_HOST=tcp://localhost:2375
```

**Path issues:**

```json
{
  "mcpServers": {
    "docker": {
      "command": "C:\\Users\\YourName\\.local\\bin\\uvx.exe",
      "args": ["mcp-docker"]
    }
  }
}
```

#### Linux Issues

**SELinux blocking access:**

```bash
# Check SELinux status
getenforce

# Temporarily disable (testing only)
sudo setenforce 0

# Permanent fix: Add policy for Docker socket
sudo chcon -t docker_socket_t /var/run/docker.sock
```

**AppArmor issues:**

```bash
# Check AppArmor status
sudo aa-status

# Disable for Docker (if needed)
sudo aa-complain /usr/bin/docker
```

**Systemd socket activation:**

```bash
# Enable Docker socket
sudo systemctl enable docker.socket
sudo systemctl start docker.socket
```

### Debugging Tips

#### Enable Debug Logging

Add debug logging to see detailed information:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "MCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

#### Check Server Output

Run the server manually to see error messages:

```bash
# Run in foreground with debug logging
MCP_LOG_LEVEL=DEBUG uvx mcp-docker

# Watch for errors in output
```

#### Validate Configuration

Use Python to validate your config:

```python
# test_config.py
from mcp_docker.config import Config

config = Config()
print("Docker:", config.docker)
print("Safety:", config.safety)
print("Server:", config.server)
```

Run with:

```bash
uv run python test_config.py
```

#### Test Docker Connection

Test Docker connection separately:

```python
# test_docker.py
from docker import DockerClient

client = DockerClient(base_url="unix:///var/run/docker.sock")
print("Docker version:", client.version())
print("Docker info:", client.info())
```

#### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Module not found: mcp_docker` | Installation issue | Reinstall with `uvx` or `pip install -e .` |
| `Cannot connect to Docker daemon` | Docker not running | Start Docker Desktop or daemon |
| `Permission denied` | Socket permissions | Add user to docker group (Linux) |
| `Operation not allowed` | Safety settings | Adjust `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS` |
| `Timeout` | Slow Docker operation | Increase `DOCKER_TIMEOUT` |
| `TLS verification failed` | Certificate issue | Check TLS certificate paths |

### Getting Help

If you're still experiencing issues:

1. **Check GitHub Issues**: [github.com/williajm/mcp_docker/issues](https://github.com/williajm/mcp_docker/issues)
2. **Create a new issue** with:
   - Python version (`python --version`)
   - Docker version (`docker --version`)
   - Operating system
   - Error messages (with debug logging enabled)
   - Configuration file (remove sensitive data)
3. **GitHub Discussions**: [github.com/williajm/mcp_docker/discussions](https://github.com/williajm/mcp_docker/discussions)

## Platform-Specific Notes

Detailed information for each operating system.

### macOS

#### Prerequisites

- macOS 10.15 (Catalina) or later
- Docker Desktop for Mac 4.0 or later
- Python 3.11+ (install via Homebrew recommended)

#### Docker Socket Location

```bash
/var/run/docker.sock
```

#### Installation

```bash
# Install Python 3.11
brew install python@3.11

# Install Docker Desktop
brew install --cask docker

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install MCP Docker
uvx mcp-docker
```

#### Configuration

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

#### Special Considerations

- **Apple Silicon (M1/M2/M3)**: Docker Desktop runs natively on ARM. Some x86_64 images may run slower through Rosetta 2.
- **Gatekeeper**: First run may prompt for security permission. Go to System Settings > Privacy & Security and allow.
- **Docker Desktop must be running**: Check menu bar for Docker icon.

### Windows

#### Prerequisites

- Windows 10 64-bit: Pro, Enterprise, or Education (Build 19041 or higher)
- Or Windows 11
- Docker Desktop for Windows 4.0 or later
- Python 3.11+ from python.org
- WSL2 (recommended) or Hyper-V

#### Docker Socket Location

```
npipe:////./pipe/docker_engine
```

Or with WSL2:

```
unix:///var/run/docker.sock
```

#### Installation

**PowerShell:**

```powershell
# Install Python 3.11 (download from python.org)
# Or use winget
winget install Python.Python.3.11

# Install Docker Desktop
winget install Docker.DockerDesktop

# Install uv
irm https://astral.sh/uv/install.ps1 | iex

# Install MCP Docker
uvx mcp-docker
```

#### Configuration

**Native Windows:**

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

**WSL2:**

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

#### Special Considerations

- **WSL2 vs Hyper-V**: WSL2 is recommended for better performance and Linux compatibility
- **Path separators**: Use forward slashes (/) or escape backslashes (\\\\) in JSON
- **Docker Desktop settings**: Enable "Expose daemon on tcp://localhost:2375 without TLS" if needed
- **Windows Defender**: May slow down Docker operations, consider adding exclusions
- **File paths**: Use Windows paths for volume mounts, even in WSL2

#### WSL2 Setup

If using WSL2:

```bash
# Inside WSL2
# Docker Desktop integration should be enabled in settings

# Test connection
docker ps

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install MCP Docker
uvx mcp-docker
```

### Linux

#### Prerequisites

- Modern Linux distribution (Ubuntu 20.04+, Debian 11+, Fedora 34+, etc.)
- Docker Engine or Docker Desktop for Linux
- Python 3.11+

#### Docker Socket Location

```bash
/var/run/docker.sock
```

#### Installation

**Ubuntu/Debian:**

```bash
# Install Python 3.11
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install MCP Docker
uvx mcp-docker
```

**Fedora/RHEL:**

```bash
# Install Python 3.11
sudo dnf install python3.11

# Install Docker
sudo dnf install docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install MCP Docker
uvx mcp-docker
```

**Arch Linux:**

```bash
# Install Python and Docker
sudo pacman -S python docker

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install MCP Docker
uvx mcp-docker
```

#### Configuration

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

#### Special Considerations

- **User permissions**: Must be in `docker` group or use `sudo`
- **SELinux**: May need to adjust policies on Fedora/RHEL
- **AppArmor**: May need to adjust profiles on Ubuntu/Debian
- **Systemd**: Docker should be enabled to start on boot
- **Rootless Docker**: Supported but uses different socket path (`$XDG_RUNTIME_DIR/docker.sock`)

#### Rootless Docker

If using rootless Docker:

```bash
# Install rootless Docker
dockerd-rootless-setuptool.sh install

# Configure MCP Docker
export DOCKER_BASE_URL="unix://$XDG_RUNTIME_DIR/docker.sock"
```

Update Claude config:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "unix:///run/user/1000/docker.sock"
      }
    }
  }
}
```

## Uninstallation

How to completely remove the MCP Docker server.

### Remove from Claude Desktop

1. Edit your Claude Desktop configuration file
2. Remove the `docker` entry from `mcpServers`
3. Restart Claude Desktop

### Uninstall Package

#### If installed with uvx

```bash
# uvx doesn't install permanently, but you can clear cache
uv cache clean mcp-docker
```

#### If installed with uv from source

```bash
# Remove the cloned repository
rm -rf /path/to/mcp_docker

# Optional: Remove virtual environment
rm -rf .venv
```

#### If installed with pip

```bash
# Deactivate virtual environment if active
deactivate

# Uninstall package
pip uninstall mcp-docker

# Remove virtual environment
rm -rf /path/to/venv
```

### Clean Up Configuration

Remove any configuration files:

```bash
# Remove .env file if created
rm /path/to/mcp_docker/.env

# Clear Docker credentials if configured
rm ~/.docker/config.json  # Be careful, this removes all Docker credentials
```

### Verify Removal

```bash
# Check that command is gone
which mcp-docker  # Should return nothing

# Check pip list
pip list | grep mcp-docker  # Should return nothing
```

### Keep Your Docker Data

Uninstalling MCP Docker does not affect your Docker installation or any containers, images, volumes, or networks. Only the MCP server interface is removed.

---

## Next Steps

After installation and configuration:

1. Read the [API Reference](API.md) to learn about available tools
2. Check out [Usage Examples](EXAMPLES.md) for practical scenarios
3. Review [Architecture](ARCHITECTURE.md) to understand how it works
4. Join the community on [GitHub Discussions](https://github.com/williajm/mcp_docker/discussions)

## Support

Need help? Here's how to get support:

- **Documentation**: Check this guide and other docs in the [docs/](../docs) directory
- **GitHub Issues**: Report bugs at [github.com/williajm/mcp_docker/issues](https://github.com/williajm/mcp_docker/issues)
- **Discussions**: Ask questions at [github.com/williajm/mcp_docker/discussions](https://github.com/williajm/mcp_docker/discussions)
- **MCP Community**: Join the [Model Context Protocol community](https://modelcontextprotocol.io)

---

**Last Updated**: October 2025
**Version**: 0.2.0
**Status**: Alpha
