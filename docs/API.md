---
layout: default
title: API Reference
---

# Docker MCP Server - API Reference

**Version:** 1.0.1
**Last Updated:** 2025-11-09

## Table of Contents

1. [Introduction](#introduction)
2. [Safety System](#safety-system)
3. [Tools](#tools)
   - [Container Tools (10)](#container-tools)
   - [Image Tools (9)](#image-tools)
   - [Network Tools (6)](#network-tools)
   - [Volume Tools (5)](#volume-tools)
   - [System Tools (6)](#system-tools)
4. [Prompts](#prompts)
5. [Resources](#resources)
6. [Error Codes and Handling](#error-codes-and-handling)

---

## Introduction

The Docker MCP Server provides 36 tools, 5 prompts, and 2 resource types for comprehensive Docker management through the Model Context Protocol (MCP). This API reference documents all available functionality, input parameters, output formats, and usage examples.

### Key Features

- **36 Docker Tools**: Complete container, image, network, volume, and system management
- **Safety System**: Three-tier safety classification (SAFE, MODERATE, DESTRUCTIVE)
- **5 AI Prompts**: Troubleshooting, optimization, compose generation, network debugging, and security auditing
- **2 Resource Types**: Real-time container logs and statistics via URI
- **Full Validation**: Input validation and error handling for all operations

---

## Safety System

All tools are classified into three safety levels:

### Safety Levels

| Level | Description | Examples | Restrictions |
|-------|-------------|----------|--------------|
| **SAFE** | Read-only operations that don't modify state | list, inspect, logs, stats | None |
| **MODERATE** | State-changing but reversible operations | start, stop, create, pull | None (default) |
| **DESTRUCTIVE** | Permanent operations that delete data | remove, prune | Requires `allow_destructive_operations=true` |

### Configuration

Safety settings can be configured via environment variables:

```bash
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true
```

### Errors

- **UnsafeOperationError**: Raised when a destructive operation is attempted without permission
- **SafetyError**: Base class for all safety-related errors

---

## Tools

### Container Tools

#### docker_list_containers

List Docker containers with optional filters.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `all` | boolean | No | `false` | Show all containers (default shows just running) |
| `filters` | object | No | `null` | Filters to apply (e.g., `{'status': ['running']}`) |

**Output Format:**

```json
{
  "containers": [
    {
      "id": "sha256:abc123...",
      "short_id": "abc123",
      "name": "my-container",
      "image": "nginx:latest",
      "status": "running",
      "labels": {}
    }
  ],
  "count": 1
}
```

**Example Usage:**

```json
{
  "tool": "docker_list_containers",
  "arguments": {
    "all": true,
    "filters": {"status": ["running", "exited"]}
  }
}
```

---

#### docker_inspect_container

Get detailed information about a Docker container.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |

**Output Format:**

```json
{
  "details": {
    "Id": "abc123...",
    "Name": "/my-container",
    "State": {...},
    "Config": {...},
    "NetworkSettings": {...}
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_inspect_container",
  "arguments": {
    "container_id": "my-container"
  }
}
```

---

#### docker_create_container

Create a new Docker container from an image.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Image name to create container from |
| `name` | string | No | `null` | Optional container name |
| `command` | string or array | No | `null` | Command to run |
| `environment` | object | No | `null` | Environment variables |
| `ports` | object | No | `null` | Port mappings (container_port: host_port) |
| `volumes` | object | No | `null` | Volume mappings |
| `detach` | boolean | No | `true` | Run container in background |
| `remove` | boolean | No | `false` | Remove container when it exits |
| `mem_limit` | string | No | `null` | Memory limit (e.g., '512m', '2g') |
| `cpu_shares` | integer | No | `null` | CPU shares (relative weight) |

**Output Format:**

```json
{
  "container_id": "abc123...",
  "name": "my-container",
  "warnings": null
}
```

**Example Usage:**

```json
{
  "tool": "docker_create_container",
  "arguments": {
    "image": "nginx:latest",
    "name": "my-nginx",
    "ports": {"80/tcp": 8080},
    "environment": {"ENV": "production"},
    "mem_limit": "512m"
  }
}
```

**Notes:**
- Container name must follow Docker naming conventions (alphanumeric, hyphens, underscores)
- Memory limit accepts units: b, k, m, g (e.g., "512m", "2g")
- Port mappings support both integer and tuple formats

---

#### docker_start_container

Start a stopped Docker container.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |

**Output Format:**

```json
{
  "container_id": "abc123...",
  "status": "running"
}
```

**Example Usage:**

```json
{
  "tool": "docker_start_container",
  "arguments": {
    "container_id": "my-container"
  }
}
```

---

#### docker_stop_container

Stop a running Docker container gracefully.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `timeout` | integer | No | `10` | Timeout in seconds before killing |

**Output Format:**

```json
{
  "container_id": "abc123...",
  "status": "exited"
}
```

**Example Usage:**

```json
{
  "tool": "docker_stop_container",
  "arguments": {
    "container_id": "my-container",
    "timeout": 30
  }
}
```

**Notes:**
- Sends SIGTERM, then SIGKILL after timeout
- Timeout of 0 means immediate SIGKILL

---

#### docker_restart_container

Restart a Docker container.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `timeout` | integer | No | `10` | Timeout in seconds before killing |

**Output Format:**

```json
{
  "container_id": "abc123...",
  "status": "running"
}
```

**Example Usage:**

```json
{
  "tool": "docker_restart_container",
  "arguments": {
    "container_id": "my-container",
    "timeout": 15
  }
}
```

---

#### docker_remove_container

Remove a Docker container.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `force` | boolean | No | `false` | Force removal of running container |
| `volumes` | boolean | No | `false` | Remove associated volumes |

**Output Format:**

```json
{
  "container_id": "abc123...",
  "removed_volumes": false
}
```

**Example Usage:**

```json
{
  "tool": "docker_remove_container",
  "arguments": {
    "container_id": "my-container",
    "force": true,
    "volumes": true
  }
}
```

**Warnings:**
- This operation is irreversible
- Using `force=true` on running containers may cause data loss
- Using `volumes=true` permanently deletes volume data

---

#### docker_container_logs

Get logs from a Docker container.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `tail` | integer or string | No | `"all"` | Number of lines to show from end |
| `since` | string | No | `null` | Show logs since timestamp or relative (e.g., '1h') |
| `until` | string | No | `null` | Show logs until timestamp |
| `timestamps` | boolean | No | `false` | Show timestamps |
| `follow` | boolean | No | `false` | Follow log output |

**Output Format:**

```json
{
  "logs": "Log line 1\nLog line 2\n...",
  "container_id": "abc123..."
}
```

**Example Usage:**

```json
{
  "tool": "docker_container_logs",
  "arguments": {
    "container_id": "my-container",
    "tail": 100,
    "timestamps": true,
    "since": "1h"
  }
}
```

**Notes:**
- `since` accepts ISO 8601 timestamps or relative time (e.g., "1h", "30m")
- `follow=true` streams logs continuously (use with caution)

---

#### docker_exec_command

Execute a command in a running Docker container.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `command` | string or array | Yes | - | Command to execute |
| `workdir` | string | No | `null` | Working directory for command |
| `user` | string | No | `null` | User to run command as |
| `environment` | object | No | `null` | Environment variables |
| `privileged` | boolean | No | `false` | Run with elevated privileges |

**Output Format:**

```json
{
  "exit_code": 0,
  "output": "Command output here..."
}
```

**Example Usage:**

```json
{
  "tool": "docker_exec_command",
  "arguments": {
    "container_id": "my-container",
    "command": ["ls", "-la", "/app"],
    "user": "root",
    "workdir": "/app"
  }
}
```

**Notes:**
- Command can be a string or array of strings
- Non-zero exit codes indicate command failure
- `privileged=true` requires special permissions

---

#### docker_container_stats

Get resource usage statistics for a Docker container.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `container_id` | string | Yes | - | Container ID or name |
| `stream` | boolean | No | `false` | Stream stats continuously |

**Output Format:**

```json
{
  "stats": {
    "cpu_stats": {...},
    "memory_stats": {...},
    "networks": {...},
    "blkio_stats": {...}
  },
  "container_id": "abc123..."
}
```

**Example Usage:**

```json
{
  "tool": "docker_container_stats",
  "arguments": {
    "container_id": "my-container",
    "stream": false
  }
}
```

**Notes:**
- Container must be running to get stats
- `stream=false` returns single snapshot
- Stats include CPU, memory, network, and block I/O

---

### Image Tools

#### docker_list_images

List Docker images with optional filters.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `all` | boolean | No | `false` | Show all images including intermediates |
| `filters` | object | No | `null` | Filters to apply (e.g., `{'dangling': ['true']}`) |

**Output Format:**

```json
{
  "images": [
    {
      "id": "sha256:def456...",
      "short_id": "def456",
      "tags": ["nginx:latest"],
      "labels": {},
      "size": 142000000
    }
  ],
  "count": 1
}
```

**Example Usage:**

```json
{
  "tool": "docker_list_images",
  "arguments": {
    "all": true,
    "filters": {"dangling": ["false"]}
  }
}
```

---

#### docker_inspect_image

Get detailed information about a Docker image.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image_name` | string | Yes | - | Image name or ID |

**Output Format:**

```json
{
  "details": {
    "Id": "sha256:def456...",
    "RepoTags": ["nginx:latest"],
    "Size": 142000000,
    "Config": {...},
    "RootFS": {...}
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_inspect_image",
  "arguments": {
    "image_name": "nginx:latest"
  }
}
```

---

#### docker_pull_image

Pull a Docker image from a registry.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Image name (e.g., 'ubuntu:22.04') |
| `tag` | string | No | `null` | Optional tag (if not in image name) |
| `all_tags` | boolean | No | `false` | Pull all tags |
| `platform` | string | No | `null` | Platform (e.g., 'linux/amd64') |

**Output Format:**

```json
{
  "image": "ubuntu:22.04",
  "id": "sha256:abc123...",
  "tags": ["ubuntu:22.04"]
}
```

**Example Usage:**

```json
{
  "tool": "docker_pull_image",
  "arguments": {
    "image": "ubuntu",
    "tag": "22.04",
    "platform": "linux/amd64"
  }
}
```

**Notes:**
- Image name must be valid registry format
- Platform selection useful for multi-arch images
- Large images may take time to download

---

#### docker_build_image

Build a Docker image from a Dockerfile.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `path` | string | Yes | - | Path to build context |
| `tag` | string | No | `null` | Tag for the image |
| `dockerfile` | string | No | `"Dockerfile"` | Path to Dockerfile |
| `buildargs` | object | No | `null` | Build arguments |
| `nocache` | boolean | No | `false` | Do not use cache |
| `rm` | boolean | No | `true` | Remove intermediate containers |
| `pull` | boolean | No | `false` | Always pull newer base images |

**Output Format:**

```json
{
  "image_id": "sha256:xyz789...",
  "tags": ["my-app:latest"],
  "logs": ["Step 1/5 : FROM node:18", "..."]
}
```

**Example Usage:**

```json
{
  "tool": "docker_build_image",
  "arguments": {
    "path": "/app",
    "tag": "my-app:v1.0",
    "dockerfile": "Dockerfile.prod",
    "buildargs": {"NODE_ENV": "production"},
    "nocache": true
  }
}
```

**Notes:**
- Path must be accessible to Docker daemon
- Build logs are returned for debugging
- Build args override Dockerfile ARG instructions

---

#### docker_push_image

Push a Docker image to a registry.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Image name to push |
| `tag` | string | No | `null` | Optional tag |

**Output Format:**

```json
{
  "image": "myregistry/my-app:latest",
  "status": "pushed"
}
```

**Example Usage:**

```json
{
  "tool": "docker_push_image",
  "arguments": {
    "image": "myregistry/my-app",
    "tag": "latest"
  }
}
```

**Notes:**
- Requires authentication to registry
- Image must be properly tagged for registry

---

#### docker_tag_image

Tag a Docker image.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Source image name or ID |
| `repository` | string | Yes | - | Target repository |
| `tag` | string | No | `"latest"` | Tag name |

**Output Format:**

```json
{
  "source": "nginx:latest",
  "target": "myregistry/nginx:v1.0"
}
```

**Example Usage:**

```json
{
  "tool": "docker_tag_image",
  "arguments": {
    "image": "nginx:latest",
    "repository": "myregistry/nginx",
    "tag": "v1.0"
  }
}
```

---

#### docker_remove_image

Remove a Docker image.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Image name or ID |
| `force` | boolean | No | `false` | Force removal |
| `noprune` | boolean | No | `false` | Do not delete untagged parents |

**Output Format:**

```json
{
  "deleted": [
    {"Deleted": "sha256:abc123..."}
  ]
}
```

**Example Usage:**

```json
{
  "tool": "docker_remove_image",
  "arguments": {
    "image": "old-image:v1.0",
    "force": true
  }
}
```

**Warnings:**
- This operation is irreversible
- Cannot remove images used by containers without `force=true`

---

#### docker_prune_images

Remove unused Docker images.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `all` | boolean | No | `false` | Remove all unused images, not just dangling ones. Equivalent to 'docker image prune -a'. When False (default), only removes dangling images (untagged intermediate layers). When True, removes all images not used by any container. NOTE: This still only removes UNUSED images. To remove ALL images including tagged ones, use force_all=true. |
| `filters` | object | No | `null` | Filters to apply as key-value pairs. Examples: {'dangling': ['true']}, {'until': '24h'}, {'label': ['env=test']} |
| `force_all` | boolean | No | `false` | Force remove ALL images, even if tagged or in use. USE THIS when user asks to 'remove all images', 'delete all images', or 'prune all images'. When True, removes EVERY image regardless of tags, names, or container usage. WARNING: This is extremely destructive and will delete all images. Requires user confirmation. |

**Output Format:**

```json
{
  "deleted": [
    {"Deleted": "sha256:abc123..."}
  ],
  "space_reclaimed": 1234567890
}
```

**Example Usage:**

```json
{
  "tool": "docker_prune_images",
  "arguments": {
    "all": false,
    "filters": {"dangling": ["true"]}
  }
}
```

**Example: Remove ALL images**

```json
{
  "tool": "docker_prune_images",
  "arguments": {
    "force_all": true
  }
}
```

**Warnings:**
- By default, removes only UNUSED/dangling images
- Use `all=true` to remove all unused images (not just dangling)
- Use `force_all=true` to remove ALL images including tagged ones (extremely destructive)
- When user says "remove all images" or "delete all images", use `force_all=true`

---

#### docker_image_history

View the history of a Docker image.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | Yes | - | Image name or ID |

**Output Format:**

```json
{
  "history": [
    {
      "Id": "sha256:layer1...",
      "Created": 1634567890,
      "CreatedBy": "/bin/sh -c apt-get update",
      "Size": 12345678
    }
  ]
}
```

**Example Usage:**

```json
{
  "tool": "docker_image_history",
  "arguments": {
    "image": "nginx:latest"
  }
}
```

---

### Network Tools

#### docker_list_networks

List Docker networks with optional filters.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filters` | object | No | `null` | Filters to apply (e.g., `{'driver': ['bridge']}`) |

**Output Format:**

```json
{
  "networks": [
    {
      "id": "net123...",
      "short_id": "net123",
      "name": "bridge",
      "driver": "bridge",
      "scope": "local",
      "labels": {}
    }
  ],
  "count": 1
}
```

**Example Usage:**

```json
{
  "tool": "docker_list_networks",
  "arguments": {
    "filters": {"driver": ["bridge"]}
  }
}
```

---

#### docker_inspect_network

Get detailed information about a Docker network.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network_id` | string | Yes | - | Network ID or name |

**Output Format:**

```json
{
  "details": {
    "Id": "net123...",
    "Name": "bridge",
    "Driver": "bridge",
    "Containers": {...},
    "IPAM": {...}
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_inspect_network",
  "arguments": {
    "network_id": "bridge"
  }
}
```

---

#### docker_create_network

Create a new Docker network.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Network name |
| `driver` | string | No | `"bridge"` | Network driver (bridge, overlay, etc.) |
| `options` | object | No | `null` | Driver options |
| `ipam` | object | No | `null` | IPAM configuration |
| `internal` | boolean | No | `false` | Restrict external access |
| `labels` | object | No | `null` | Network labels |
| `enable_ipv6` | boolean | No | `false` | Enable IPv6 |
| `attachable` | boolean | No | `false` | Enable manual container attachment |

**Output Format:**

```json
{
  "network_id": "net123...",
  "name": "my-network",
  "warnings": null
}
```

**Example Usage:**

```json
{
  "tool": "docker_create_network",
  "arguments": {
    "name": "my-network",
    "driver": "bridge",
    "internal": false,
    "labels": {"project": "myapp"}
  }
}
```

---

#### docker_connect_container

Connect a container to a Docker network.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network_id` | string | Yes | - | Network ID or name |
| `container_id` | string | Yes | - | Container ID or name |
| `aliases` | array | No | `null` | Network-scoped aliases |
| `ipv4_address` | string | No | `null` | IPv4 address |
| `ipv6_address` | string | No | `null` | IPv6 address |
| `links` | array | No | `null` | Legacy container links |

**Output Format:**

```json
{
  "network_id": "net123...",
  "container_id": "abc123...",
  "status": "connected"
}
```

**Example Usage:**

```json
{
  "tool": "docker_connect_container",
  "arguments": {
    "network_id": "my-network",
    "container_id": "my-container",
    "aliases": ["web", "frontend"]
  }
}
```

---

#### docker_disconnect_container

Disconnect a container from a Docker network.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network_id` | string | Yes | - | Network ID or name |
| `container_id` | string | Yes | - | Container ID or name |
| `force` | boolean | No | `false` | Force disconnection |

**Output Format:**

```json
{
  "network_id": "net123...",
  "container_id": "abc123...",
  "status": "disconnected"
}
```

**Example Usage:**

```json
{
  "tool": "docker_disconnect_container",
  "arguments": {
    "network_id": "my-network",
    "container_id": "my-container",
    "force": false
  }
}
```

---

#### docker_remove_network

Remove a Docker network.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network_id` | string | Yes | - | Network ID or name |

**Output Format:**

```json
{
  "network_id": "net123..."
}
```

**Example Usage:**

```json
{
  "tool": "docker_remove_network",
  "arguments": {
    "network_id": "old-network"
  }
}
```

**Warnings:**
- Cannot remove networks with connected containers
- This operation is irreversible

---

### Volume Tools

#### docker_list_volumes

List Docker volumes with optional filters.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filters` | object | No | `null` | Filters to apply (e.g., `{'dangling': ['true']}`) |

**Output Format:**

```json
{
  "volumes": [
    {
      "name": "my-volume",
      "driver": "local",
      "mountpoint": "/var/lib/docker/volumes/my-volume/_data",
      "labels": {},
      "scope": "local"
    }
  ],
  "count": 1
}
```

**Example Usage:**

```json
{
  "tool": "docker_list_volumes",
  "arguments": {
    "filters": {"dangling": ["false"]}
  }
}
```

---

#### docker_inspect_volume

Get detailed information about a Docker volume.

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `volume_name` | string | Yes | - | Volume name |

**Output Format:**

```json
{
  "details": {
    "Name": "my-volume",
    "Driver": "local",
    "Mountpoint": "/var/lib/docker/volumes/my-volume/_data",
    "Labels": {},
    "Scope": "local"
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_inspect_volume",
  "arguments": {
    "volume_name": "my-volume"
  }
}
```

---

#### docker_create_volume

Create a new Docker volume.

**Safety Level:** MODERATE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | No | `null` | Volume name (auto-generated if not set) |
| `driver` | string | No | `"local"` | Volume driver |
| `driver_opts` | object | No | `null` | Driver options |
| `labels` | object | No | `null` | Volume labels |

**Output Format:**

```json
{
  "name": "my-volume",
  "driver": "local",
  "mountpoint": "/var/lib/docker/volumes/my-volume/_data"
}
```

**Example Usage:**

```json
{
  "tool": "docker_create_volume",
  "arguments": {
    "name": "my-data",
    "driver": "local",
    "labels": {"project": "myapp"}
  }
}
```

---

#### docker_remove_volume

Remove a Docker volume.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `volume_name` | string | Yes | - | Volume name |
| `force` | boolean | No | `false` | Force removal |

**Output Format:**

```json
{
  "volume_name": "my-volume"
}
```

**Example Usage:**

```json
{
  "tool": "docker_remove_volume",
  "arguments": {
    "volume_name": "old-volume",
    "force": true
  }
}
```

**Warnings:**
- This operation permanently deletes data
- Cannot remove volumes in use without `force=true`

---

#### docker_prune_volumes

Remove unused Docker volumes.

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filters` | object | No | `null` | Filters to apply as key-value pairs. Examples: {'label': ['env=test']}, {'dangling': ['true']}. NOTE: Filters only apply when force_all=false (standard prune mode). |
| `force_all` | boolean | No | `false` | Force remove ALL volumes, even if named or in use. USE THIS when user asks to 'remove all volumes', 'delete all volumes', or 'prune all volumes'. When True, removes EVERY volume regardless of name or usage. WARNING: This is extremely destructive and will delete all volumes. Requires user confirmation. |

**Output Format:**

```json
{
  "deleted": ["volume1", "volume2"],
  "space_reclaimed": 1234567890
}
```

**Example Usage:**

```json
{
  "tool": "docker_prune_volumes",
  "arguments": {
    "filters": {"label": ["env=test"]}
  }
}
```

**Example: Remove ALL volumes**

```json
{
  "tool": "docker_prune_volumes",
  "arguments": {
    "force_all": true
  }
}
```

**Warnings:**
- By default, removes only UNUSED volumes
- Use `force_all=true` to remove ALL volumes including named ones (extremely destructive)
- When user says "remove all volumes" or "delete all volumes", use `force_all=true`
- This operation permanently deletes data

---

### System Tools

#### docker_system_info

Get Docker system information.

**Safety Level:** SAFE

**Input Parameters:** None

**Output Format:**

```json
{
  "info": {
    "ID": "ABC123...",
    "Containers": 5,
    "Images": 10,
    "Driver": "overlay2",
    "MemTotal": 16000000000,
    "NCPU": 8,
    "DockerRootDir": "/var/lib/docker",
    "ServerVersion": "24.0.0"
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_system_info",
  "arguments": {}
}
```

---

#### docker_system_df

Get Docker disk usage statistics.

**Safety Level:** SAFE

**Input Parameters:** None

**Output Format:**

```json
{
  "images": {
    "Active": 5,
    "Size": 1234567890,
    "Reclaimable": 123456789
  },
  "containers": {
    "Active": 3,
    "Size": 987654321,
    "Reclaimable": 98765432
  },
  "volumes": {
    "Active": 2,
    "Size": 456789123,
    "Reclaimable": 45678912
  },
  "build_cache": {...}
}
```

**Example Usage:**

```json
{
  "tool": "docker_system_df",
  "arguments": {}
}
```

---

#### docker_system_prune

Prune Docker resources. By default, removes only UNUSED resources (stopped containers, dangling images, unused networks).

**Safety Level:** DESTRUCTIVE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `all` | boolean | No | `false` | Remove all unused images, not just dangling ones. Equivalent to 'docker system prune -a'. When False (default), only removes dangling images. When True, removes all images not used by any container. NOTE: This still only removes UNUSED images. To remove ALL images including tagged ones, use force_all=true. |
| `filters` | object | No | `null` | Filters to apply as key-value pairs. Examples: {'until': '24h'}, {'label': ['env=test']} |
| `volumes` | boolean | No | `false` | Include volumes in the prune operation. When False (default), volumes are not pruned. When True, prunes unused volumes. NOTE: This still only removes UNUSED volumes. To remove ALL volumes including named ones, use force_all=true. |
| `force_all` | boolean | No | `false` | Force remove ALL images and volumes, even if tagged/named or in use. USE THIS when user asks to 'remove all', 'delete all', 'clean everything', or 'prune all volumes/images'. When True, removes EVERY image and volume regardless of tags, names, or usage. WARNING: This is extremely destructive and will delete everything. Requires user confirmation. |

**Output Format:**

```json
{
  "containers_deleted": ["abc123...", "def456..."],
  "images_deleted": [{"Deleted": "sha256:..."}],
  "networks_deleted": ["net123..."],
  "volumes_deleted": ["vol1", "vol2"],
  "space_reclaimed": 1234567890
}
```

**Example Usage:**

```json
{
  "tool": "docker_system_prune",
  "arguments": {
    "all": false,
    "volumes": false,
    "filters": {}
  }
}
```

**Example: Remove ALL resources (extremely destructive)**

```json
{
  "tool": "docker_system_prune",
  "arguments": {
    "all": true,
    "volumes": true,
    "force_all": true
  }
}
```

**Warnings:**
- By default, removes only UNUSED resources (stopped containers, dangling images, unused networks)
- Use `all=true` to include all unused images (not just dangling)
- Use `volumes=true` to include unused volumes
- Use `force_all=true` to remove ALL images and volumes including tagged/named ones (extremely destructive)
- When user says "remove all" or "delete everything", use `force_all=true`
- This operation is irreversible - use with extreme caution

---

#### docker_version

Get Docker version information.

**Safety Level:** SAFE

**Input Parameters:** None

**Output Format:**

```json
{
  "version": {
    "Version": "24.0.0",
    "ApiVersion": "1.43",
    "GoVersion": "go1.20.4",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "5.15.0"
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_version",
  "arguments": {}
}
```

---

#### docker_events

Stream Docker events (limited to recent events).

**Safety Level:** SAFE

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `since` | string | No | `null` | Show events since timestamp |
| `until` | string | No | `null` | Show events until timestamp |
| `filters` | object | No | `null` | Event filters |
| `decode` | boolean | No | `true` | Decode JSON events |

**Output Format:**

```json
{
  "events": [
    {
      "Type": "container",
      "Action": "start",
      "Actor": {...},
      "time": 1634567890
    }
  ],
  "count": 1
}
```

**Example Usage:**

```json
{
  "tool": "docker_events",
  "arguments": {
    "since": "2024-01-01T00:00:00Z",
    "filters": {"type": ["container"]}
  }
}
```

**Notes:**
- Limited to 100 events to prevent infinite loops
- Use filters to narrow results

---

#### docker_healthcheck

Check Docker daemon health.

**Safety Level:** SAFE

**Input Parameters:** None

**Output Format:**

```json
{
  "healthy": true,
  "message": "Docker daemon is healthy",
  "details": {
    "daemon_info": {...},
    "containers": {...},
    "images": 10
  }
}
```

**Example Usage:**

```json
{
  "tool": "docker_healthcheck",
  "arguments": {}
}
```

---

## Prompts

The Docker MCP Server provides 5 AI-powered prompts for common tasks.

### troubleshoot_container

Diagnose and troubleshoot container issues.

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `container_id` | string | Yes | Container ID or name to troubleshoot |

**Description:**

Generates an AI prompt with container state, configuration, logs, and expert troubleshooting guidance. Analyzes:
- Container status and exit codes
- Error messages and log patterns
- Configuration issues
- Resource constraints
- Network and volume problems

**Example:**

```json
{
  "prompt": "troubleshoot_container",
  "arguments": {
    "container_id": "my-failing-container"
  }
}
```

**Output:**

Returns a prompt with:
- System message: Docker troubleshooting expert context
- User message: Container details, logs, and analysis request

---

### optimize_container

Suggest optimizations for container configuration.

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `container_id` | string | Yes | Container ID or name to optimize |

**Description:**

Generates an AI prompt with container configuration, resource usage, and optimization recommendations. Suggests improvements for:
- Resource allocation (CPU, memory)
- Restart policies
- Security best practices
- Network configuration
- Volume management
- Health checks

**Example:**

```json
{
  "prompt": "optimize_container",
  "arguments": {
    "container_id": "my-container"
  }
}
```

**Output:**

Returns a prompt with:
- System message: Docker optimization expert context
- User message: Container configuration and resource stats

---

### generate_compose

Generate a docker-compose.yml file from container configuration.

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `container_id` | string | No | Container ID or name to convert to docker-compose |
| `service_description` | string | No | Description of services to include |

**Description:**

Generates an AI prompt to create a docker-compose.yml file. Can work from:
- Existing container configuration
- Service description
- Both combined

Follows best practices:
- Version 3.8+ syntax
- Proper network and volume configuration
- Health checks and restart policies
- Environment variables and labels

**Example:**

```json
{
  "prompt": "generate_compose",
  "arguments": {
    "container_id": "my-container",
    "service_description": "Web app with Redis cache"
  }
}
```

**Output:**

Returns a prompt with:
- System message: Docker Compose expert context
- User message: Container config or service requirements

---

### debug_networking

Deep-dive analysis of container networking problems.

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `container_id` | string | Yes | Container ID or name to debug networking for |
| `target_host` | string | No | Optional target host/container to test connectivity to |

**Description:**

Generates an AI prompt with comprehensive network configuration analysis and systematic troubleshooting guidance. Provides:

**Network Configuration Extraction:**
- IP addresses, gateways, and MAC addresses for all attached networks
- Port mappings (published and unpublished)
- Container hostname and DNS settings
- Network-related log entries (connection refused, timeout, DNS errors)

**Systematic Troubleshooting Approach (6 Layers):**
1. **Network Layer (L3)**: IP connectivity, subnet configuration, gateway accessibility
2. **Transport Layer (L4)**: Port mappings, bindings, conflicts
3. **DNS Resolution**: Hostname configuration, service discovery, name resolution
4. **Network Driver Issues**: Bridge/overlay/host mode, network isolation
5. **Common Problems**: Firewall interference, MTU misconfigurations, namespace issues
6. **Debugging Commands**: Suggests docker exec commands (ping, nc, nslookup, curl)

**Example:**

```json
{
  "prompt": "debug_networking",
  "arguments": {
    "container_id": "my-webapp",
    "target_host": "database"
  }
}
```

**Output:**

Returns a prompt with:
- System message: Docker networking expert with systematic L3-L7 troubleshooting approach
- User message: Complete network configuration, port mappings, and relevant error logs

**Use Cases:**
- Container cannot reach external services
- Port mapping issues and conflicts
- DNS resolution failures
- Inter-container communication problems
- Network driver or firewall interference

---

### security_audit

Comprehensive security analysis of containers and configurations.

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `container_id` | string | No | Container ID or name to audit (audits all containers including stopped ones if not provided) |

**Description:**

Generates an AI prompt with comprehensive security analysis following CIS Docker Benchmark best practices. Analyzes:

**Security Configuration:**
- Privileged mode detection
- Linux capabilities assessment
- User configuration (root vs. non-root)
- Exposed ports and network exposure
- Volume mounts (sensitive paths like /etc/passwd, /root/.ssh)
- Environment variables (secrets detection)

**Security Controls:**
- Read-only root filesystem
- Security options (AppArmor, SELinux profiles)
- Resource limits (memory, CPU)
- Restart policies
- Network isolation

**Security Checklist (8-Point CIS Benchmark):**
1. Container runs as non-root user
2. Root filesystem is read-only
3. No privileged mode
4. Capabilities are dropped/limited
5. No sensitive host mounts
6. Security profiles active (AppArmor/SELinux)
7. Resource limits configured
8. No secrets in environment variables

**Compliance Mapping:**
- PCI-DSS requirements
- HIPAA security rules
- SOC2 controls

**Risk Prioritization:**
- Critical: Privileged containers, root user, sensitive mounts
- High: Missing security profiles, excessive capabilities
- Medium: Missing resource limits, exposed ports
- Low: Minor configuration improvements

**Example:**

```json
{
  "prompt": "security_audit",
  "arguments": {
    "container_id": "production-webapp"
  }
}
```

Or audit all containers (including stopped ones):

```json
{
  "prompt": "security_audit",
  "arguments": {}
}
```

**Output:**

Returns a prompt with:
- System message: Docker security expert with CIS Benchmark and compliance knowledge
- User message: Complete security configuration analysis with prioritized findings

**Use Cases:**
- Pre-production security review
- Compliance auditing (PCI-DSS, HIPAA, SOC2)
- Security hardening recommendations
- Identifying privilege escalation risks
- Detecting exposed secrets and sensitive data

---

## Resources

The Docker MCP Server exposes 2 resource types accessible via URI.

### Container Logs Resource

**URI Pattern:** `container://logs/{container_id}`

**MIME Type:** `text/plain`

**Description:** Real-time access to container logs.

**Parameters:**
- `tail`: Number of lines from end (default: 100)
- `follow`: Stream logs continuously (default: false)

**Example URI:**
```
container://logs/my-container
```

**Example Response:**
```
2024-01-01 12:00:00 [INFO] Application started
2024-01-01 12:00:01 [INFO] Listening on port 8080
...
```

**Notes:**
- Logs are UTF-8 decoded
- Follow mode not recommended for resources (use tool instead)
- Automatically listed for all containers

---

### Container Stats Resource

**URI Pattern:** `container://stats/{container_id}`

**MIME Type:** `text/plain`

**Description:** Resource usage statistics for running containers.

**Example URI:**
```
container://stats/my-container
```

**Example Response:**
```
Container Statistics for abc123
==========================================

CPU:
  Online CPUs: 8
  Total Usage: 123456789
  System Usage: 987654321

Memory:
  Usage: 256.50 MB
  Limit: 512.00 MB
  Percentage: 50.10%

Network:
  eth0: RX 1234.56 KB, TX 5678.90 KB

Block I/O:
  {...}
```

**Notes:**
- Only available for running containers
- Single snapshot (non-streaming)
- Formatted for readability

---

## Error Codes and Handling

### Error Hierarchy

All errors inherit from `MCPDockerError`:

```
MCPDockerError (base)
├── DockerConnectionError
├── DockerHealthCheckError
├── DockerOperationError
├── ValidationError
├── SafetyError
│   └── UnsafeOperationError
├── ContainerNotFound
├── ImageNotFound
├── NetworkNotFound
└── VolumeNotFound
```

### Common Error Codes

| Error Type | Description | HTTP Analogy | Recovery |
|------------|-------------|--------------|----------|
| `ContainerNotFound` | Container doesn't exist | 404 | Verify container ID/name |
| `ImageNotFound` | Image doesn't exist | 404 | Pull image first |
| `NetworkNotFound` | Network doesn't exist | 404 | Create network first |
| `VolumeNotFound` | Volume doesn't exist | 404 | Create volume first |
| `DockerConnectionError` | Can't connect to daemon | 503 | Check Docker daemon |
| `DockerOperationError` | Operation failed | 500 | Check logs, permissions |
| `ValidationError` | Invalid input | 400 | Fix input parameters |
| `UnsafeOperationError` | Destructive op blocked | 403 | Enable destructive ops |
| `SafetyError` | Safety check failed | 403 | Review safety settings |

### Error Response Format

All tool errors return:

```json
{
  "success": false,
  "error": "Error message here",
  "error_type": "ContainerNotFound"
}
```

### Best Practices

1. **Always check success field** before processing results
2. **Log error_type** for debugging and monitoring
3. **Handle NotFound errors** gracefully (resource may have been deleted)
4. **Retry DockerOperationError** with exponential backoff
5. **Don't retry ValidationError** - fix input instead
6. **Check Docker daemon** on DockerConnectionError

### Example Error Handling

```python
result = await call_tool("docker_start_container", {"container_id": "abc123"})

if not result["success"]:
    error_type = result["error_type"]

    if error_type == "ContainerNotFound":
        # Container was deleted
        print("Container no longer exists")
    elif error_type == "DockerOperationError":
        # Retry operation
        print("Operation failed, retrying...")
    elif error_type == "UnsafeOperationError":
        # Need to enable safety setting
        print("Enable destructive operations first")
    else:
        # Unknown error
        print(f"Error: {result['error']}")
```

---

## Appendix

### Safety Configuration Reference

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS` | boolean | `false` | Allow destructive operations (rm, prune) |
| `SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE` | boolean | `false` | Require confirmation for destructive ops |

### Tool Count by Category

- **Container Tools:** 10 tools
- **Image Tools:** 9 tools
- **Network Tools:** 6 tools
- **Volume Tools:** 5 tools
- **System Tools:** 6 tools
- **Total:** 36 tools

### Safety Level Distribution

- **SAFE:** 17 tools (read-only operations)
- **MODERATE:** 12 tools (state-changing operations)
- **DESTRUCTIVE:** 7 tools (permanent deletions)

---

**End of API Reference**

For implementation details, see the [User Guide](USER_GUIDE.md).
For development information, see [DEVELOPMENT.md](DEVELOPMENT.md).
