# Development Guide

## Platform-Specific Virtual Environments

This project uses **platform-specific virtual environments** to avoid conflicts when working across Windows and WSL.

### Why This Matters

When the same repository is accessed from both Windows and WSL:
- **Windows** creates `.venv` with Windows-specific files (`.exe`, `.dll`, etc.)
- **WSL/Linux** creates `.venv` with Linux-specific files (symlinks, `lib64 -> lib`, etc.)
- These are **incompatible** and cause errors like:
  - `Access is denied (os error 5)`
  - `No pyvenv.cfg file`
  - `failed to remove file ... being used by another process`

### Solution: Separate Virtual Environments

We use **different venv directory names** for each platform:

| Platform | Virtual Env Directory | Usage |
|----------|----------------------|-------|
| **Windows** | `.venv-win` | Claude Desktop, Windows development |
| **WSL/Linux** | `.venv-wsl` | Claude Code (WSL), Linux development |
| `.venv` | **DO NOT USE** | Generic fallback (can cause conflicts) |

### Configuration

#### Claude Desktop (Windows)
The Claude Desktop config uses `UV_PROJECT_ENVIRONMENT` to force `.venv-win`:

```json
{
  "mcpServers": {
    "mcp_docker": {
      "command": "uv",
      "args": ["--directory", "E:\\path\\to\\mcp_docker", "run", "mcp-docker"],
      "env": {
        "UV_PROJECT_ENVIRONMENT": ".venv-win"
      }
    }
  }
}
```

**Location:** `%APPDATA%\Claude\claude_desktop_config.json`

#### Claude Code / WSL Development

**Method 1: Manual (Simple)**

When you start working on this project in WSL, source the `.envrc` file:

```bash
cd /path/to/mcp_docker
source .envrc       # Sets UV_PROJECT_ENVIRONMENT=".venv-wsl"
uv sync             # Creates/uses .venv-wsl
```

**Method 2: Automatic (Recommended)**

Install `direnv` for automatic environment loading:

```bash
# Install direnv
sudo apt install direnv  # Ubuntu/Debian
# OR
brew install direnv      # macOS/Homebrew

# Add to ~/.bashrc (one-time setup)
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
source ~/.bashrc

# Allow .envrc in this project (one-time setup)
cd /path/to/mcp_docker
direnv allow

# Now it auto-loads when you cd into the directory!
cd /path/to/mcp_docker  # Automatically sets UV_PROJECT_ENVIRONMENT
```

Then use `uv` normally:
```bash
uv sync           # Creates/uses .venv-wsl
uv run pytest     # Uses .venv-wsl
uv run mcp-docker # Uses .venv-wsl
```

#### Manual Creation (if needed)

**Windows (PowerShell):**
```powershell
$env:UV_PROJECT_ENVIRONMENT = ".venv-win"
uv sync
```

**WSL/Linux (Bash):**
```bash
export UV_PROJECT_ENVIRONMENT=".venv-wsl"
uv sync
```

### .gitignore

The `.gitignore` file excludes all platform-specific venvs:
```gitignore
.venv
.venv-*           # Platform-specific venvs (.venv-win, .venv-wsl, etc.)
```

### Cleanup

If you encounter venv conflicts:

**Remove all venvs and restart:**
```bash
# In WSL
rm -rf .venv .venv-win .venv-wsl

# Then restart Claude Desktop or run:
uv sync  # With UV_PROJECT_ENVIRONMENT set
```

### Best Practices

1. **Never manually create `.venv`** - Always use `.venv-win` or `.venv-wsl`
2. **Set `UV_PROJECT_ENVIRONMENT` before running any `uv` commands**
3. **Restart Claude Desktop after cleaning up venvs** - It will recreate `.venv-win`
4. **Don't commit venv directories** - They're in `.gitignore`

### Troubleshooting

**Problem:** `Access is denied (os error 5)` or `file being used by another process`
- **Cause:** Windows venv has locked files
- **Fix:** Close all Python processes, restart Claude Desktop, or reboot

**Problem:** `No pyvenv.cfg file`
- **Cause:** Corrupted or mixed venv
- **Fix:** Delete the venv directory and let `uv` recreate it

**Problem:** `failed to remove directory .venv/Lib`
- **Cause:** Cross-platform venv conflict
- **Fix:** Use platform-specific venvs (`.venv-win` / `.venv-wsl`)

### Alternative: Separate Working Directories

If you prefer, you can clone the repo twice:
```bash
# Windows location
E:\code\git_repos\williajm\mcp_docker\     # Uses .venv normally

# WSL location
/home/jmw/code/git_repos/williajm/mcp_docker/  # Uses .venv normally
```

This avoids the shared filesystem issue entirely but requires managing two copies.

---

**Recommendation:** Use platform-specific venvs (`.venv-win` / `.venv-wsl`) as documented above. It's cleaner and keeps everything in one repository.
