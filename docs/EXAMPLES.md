---
layout: default
title: Examples
---

# Docker MCP Server - Usage Examples

**Version:** 0.2.0
**Last Updated:** 2025-10-28

## Table of Contents

1. [Introduction](#introduction)
2. [Container Health Checks](#1-container-health-checks)
3. [Application Deployment](#2-application-deployment)
4. [Resource Cleanup](#3-resource-cleanup)
5. [Troubleshooting Workflows](#4-troubleshooting-workflows)
6. [Multi-Container Applications](#5-multi-container-applications)
7. [Development Workflows](#6-development-workflows)
8. [CI/CD Integration](#7-cicd-integration)
9. [Resource Monitoring](#8-resource-monitoring)
10. [Network Configuration](#9-network-configuration)

---

## Introduction

This document provides comprehensive, real-world examples of using the Docker MCP Server through Claude. Each example includes:

- Complete conversation flows showing how users interact with Claude
- Expected outputs from Docker tools
- Explanations of what's happening at each step
- Practical use cases and best practices

These examples assume you have:
- Docker MCP Server configured in Claude Desktop
- Docker daemon running locally
- Basic familiarity with Docker concepts

---

## 1. Container Health Checks

### Use Case: Diagnosing a Failing Web Application

A production web application container keeps restarting. Let's diagnose the problem using logs and stats.

#### Conversation Example

**User:**
> My nginx container "web-app" keeps restarting. Can you help me figure out what's wrong?

**Claude:**
> I'll help diagnose the issue. Let me check the container status and logs.

*Claude uses: `docker_list_containers`*

```json
{
  "all": true,
  "filters": {"name": ["web-app"]}
}
```

**Output:**
```json
{
  "containers": [
    {
      "id": "a1b2c3d4e5f6",
      "short_id": "a1b2c3",
      "name": "web-app",
      "image": "nginx:latest",
      "status": "restarting",
      "labels": {}
    }
  ],
  "count": 1
}
```

**Claude:**
> The container is in a restarting state. Let me get detailed information and logs.

*Claude uses: `docker_inspect_container`*

```json
{
  "container_id": "web-app"
}
```

**Output:**
```json
{
  "details": {
    "Id": "a1b2c3d4e5f6...",
    "Name": "/web-app",
    "State": {
      "Status": "restarting",
      "Running": false,
      "ExitCode": 1,
      "Error": "",
      "RestartCount": 12
    },
    "Config": {
      "Image": "nginx:latest",
      "Cmd": ["nginx", "-g", "daemon off;"]
    },
    "HostConfig": {
      "RestartPolicy": {
        "Name": "always"
      }
    }
  }
}
```

**Claude:**
> The container has restarted 12 times with exit code 1. Let me check the logs to see what's failing.

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "web-app",
  "tail": 50,
  "timestamps": true
}
```

**Output:**
```json
{
  "logs": "2025-10-24T10:15:32.123Z nginx: [emerg] open() \"/etc/nginx/conf.d/default.conf\" failed (2: No such file or directory)\n2025-10-24T10:15:32.124Z nginx: configuration file /etc/nginx/nginx.conf test failed\n..."
}
```

**Claude:**
> I found the issue! The container is failing because it can't find the configuration file at `/etc/nginx/conf.d/default.conf`. Here's what's happening:

> **Problem:** The nginx configuration file is missing, causing nginx to fail on startup.

> **Root Cause:** This typically happens when:
> 1. A volume mount is overriding the default config directory
> 2. The configuration file was deleted or moved
> 3. There's a permissions issue

> **Solution:**
> 1. Stop the container to prevent infinite restart loop
> 2. Check volume mounts to ensure they're not overriding the config directory
> 3. Either provide a valid config file or remove the problematic volume mount

> Would you like me to stop the container and help you fix the configuration?

#### What's Happening

1. **List containers with filters** - Find the specific container by name
2. **Inspect container** - Get detailed state information including restart count and exit code
3. **Get logs** - Read error messages to identify the root cause
4. **Analysis** - Claude correlates the exit code, restart count, and error messages to diagnose the issue

#### Key Takeaways

- Always check container status before diving into logs
- Exit codes provide important clues (0 = success, non-zero = failure)
- Recent logs (tail=50) are usually sufficient for diagnosis
- Timestamps help identify if it's an ongoing or intermittent issue

---

## 2. Application Deployment

### Use Case: Deploying a Complete Web Application Stack

Deploy a Flask web application with Redis for session storage.

#### Conversation Example

**User:**
> I need to deploy a Flask application with Redis. The Flask app is in the image "myregistry/flask-app:v1.2.3" and needs to connect to Redis on port 6379. Expose the Flask app on port 8080.

**Claude:**
> I'll help you deploy this application stack. Let me set this up step by step:
> 1. Pull the Flask application image
> 2. Pull the Redis image
> 3. Create a custom network for the services
> 4. Start Redis container
> 5. Start Flask container connected to Redis

*Claude uses: `docker_pull_image`*

```json
{
  "image": "myregistry/flask-app:v1.2.3"
}
```

**Output:**
```json
{
  "image_id": "sha256:abc123...",
  "tags": ["myregistry/flask-app:v1.2.3"],
  "status": "Image pulled successfully"
}
```

*Claude uses: `docker_pull_image`*

```json
{
  "image": "redis:7-alpine"
}
```

**Output:**
```json
{
  "image_id": "sha256:def456...",
  "tags": ["redis:7-alpine"],
  "status": "Image pulled successfully"
}
```

**Claude:**
> Images pulled successfully. Now creating a custom network for service communication.

*Claude uses: `docker_create_network`*

```json
{
  "name": "flask-network",
  "driver": "bridge"
}
```

**Output:**
```json
{
  "network_id": "net123abc...",
  "name": "flask-network",
  "driver": "bridge"
}
```

**Claude:**
> Network created. Starting Redis container...

*Claude uses: `docker_create_container`*

```json
{
  "image": "redis:7-alpine",
  "name": "redis-session-store",
  "detach": true,
  "network": "flask-network",
  "mem_limit": "256m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "redis-session-store"
}
```

**Output:**
```json
{
  "container_id": "redis123...",
  "status": "started"
}
```

**Claude:**
> Redis is running. Now deploying the Flask application...

*Claude uses: `docker_create_container`*

```json
{
  "image": "myregistry/flask-app:v1.2.3",
  "name": "flask-app",
  "detach": true,
  "network": "flask-network",
  "ports": {
    "5000/tcp": 8080
  },
  "environment": {
    "REDIS_HOST": "redis-session-store",
    "REDIS_PORT": "6379",
    "FLASK_ENV": "production"
  },
  "mem_limit": "512m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "flask-app"
}
```

**Claude:**
> Perfect! Your Flask application stack is now deployed. Let me verify everything is running correctly.

*Claude uses: `docker_container_stats`*

```json
{
  "container_id": "flask-app",
  "stream": false
}
```

**Output:**
```json
{
  "container_id": "flask-app",
  "memory_usage_mb": 145.3,
  "memory_limit_mb": 512.0,
  "memory_percent": 28.4,
  "cpu_percent": 2.1,
  "network_rx_mb": 0.5,
  "network_tx_mb": 0.3
}
```

**Claude:**
> Deployment complete! Here's what was set up:

> **Redis Container:**
> - Name: redis-session-store
> - Network: flask-network
> - Memory limit: 256MB
> - Status: Running

> **Flask Application:**
> - Name: flask-app
> - Exposed on: http://localhost:8080
> - Connected to Redis via: redis-session-store:6379
> - Memory usage: 145MB / 512MB (28.4%)
> - CPU usage: 2.1%
> - Status: Running

> The application is ready! You can access it at http://localhost:8080

#### What's Happening

1. **Image pull** - Download application images from registry
2. **Network creation** - Create isolated network for service communication
3. **Sequential deployment** - Start Redis first (dependency), then Flask app
4. **Configuration** - Set environment variables for service discovery
5. **Resource limits** - Set memory limits to prevent overconsumption
6. **Restart policies** - Ensure containers restart automatically
7. **Health check** - Verify deployment with resource statistics

#### Key Takeaways

- Custom networks enable service discovery by container name
- Deploy dependencies (Redis) before dependent services (Flask)
- Use environment variables for configuration
- Set resource limits for production deployments
- Restart policies ensure high availability
- Always verify deployment with stats or logs

---

## 3. Resource Cleanup

### Use Case: Cleaning Up Development Environment

After running many tests and builds, clean up unused Docker resources safely.

#### Conversation Example

**User:**
> My Docker is using too much disk space. Can you help me clean up unused resources, but keep my running containers safe?

**Claude:**
> I'll help you safely clean up unused resources. Let me first check what's consuming space.

*Claude uses: `docker_system_df`*

```json
{}
```

**Output:**
```json
{
  "images": {
    "active": 12,
    "size_mb": 4532.1,
    "reclaimable_mb": 3210.5
  },
  "containers": {
    "active": 5,
    "size_mb": 234.2,
    "reclaimable_mb": 180.0
  },
  "volumes": {
    "active": 8,
    "size_mb": 1024.7,
    "reclaimable_mb": 512.3
  },
  "build_cache": {
    "size_mb": 2048.9,
    "reclaimable_mb": 2048.9
  }
}
```

**Claude:**
> I can see significant space can be reclaimed:
> - Images: 3.2 GB reclaimable
> - Containers: 180 MB reclaimable
> - Volumes: 512 MB reclaimable
> - Build cache: 2.0 GB reclaimable
>
> Total potential savings: ~5.9 GB

> Let me safely clean up in this order:
> 1. Stopped containers
> 2. Unused images
> 3. Unused volumes
> 4. Build cache

> First, let me check which containers are stopped:

*Claude uses: `docker_list_containers`*

```json
{
  "all": true,
  "filters": {"status": ["exited", "created"]}
}
```

**Output:**
```json
{
  "containers": [
    {
      "id": "old123",
      "name": "test-container-1",
      "status": "exited",
      "image": "ubuntu:20.04"
    },
    {
      "id": "old456",
      "name": "build-temp",
      "status": "exited",
      "image": "node:16"
    }
  ],
  "count": 2
}
```

**Claude:**
> Found 2 stopped containers that can be removed. Let me remove them:

*Claude uses: `docker_remove_container`*

```json
{
  "container_id": "old123",
  "force": false,
  "volumes": true
}
```

*Claude uses: `docker_remove_container`*

```json
{
  "container_id": "old456",
  "force": false,
  "volumes": true
}
```

**Claude:**
> Stopped containers removed. Now cleaning up unused images...

*Claude uses: `docker_prune_images`*

```json
{
  "dangling": false,
  "filters": {}
}
```

**Output:**
```json
{
  "images_deleted": [
    "sha256:abc123...",
    "sha256:def456...",
    "sha256:ghi789..."
  ],
  "space_reclaimed_mb": 3210.5
}
```

**Claude:**
> Removed 3 unused images, reclaimed 3.2 GB. Now cleaning volumes...

*Claude uses: `docker_prune_volumes`*

```json
{
  "filters": {}
}
```

**Output:**
```json
{
  "volumes_deleted": [
    "volume_abc123",
    "volume_def456"
  ],
  "space_reclaimed_mb": 512.3
}
```

**Claude:**
> Excellent! Cleanup complete. Here's what was removed:
>
> **Summary:**
> - Removed 2 stopped containers
> - Removed 3 unused images (3.2 GB)
> - Removed 2 unused volumes (512 MB)
> - Total space reclaimed: ~3.7 GB
>
> **Still Running (Protected):**
> - 5 active containers
> - 12 images in use
> - 6 volumes in use
>
> Your running containers were not affected. The system is now cleaner and you have more disk space available!

**User:**
> Great! Can you also clean the build cache?

**Claude:**
> I can clean the build cache, but note that this is a destructive operation. It will remove all build cache layers, which means future builds may take longer until the cache is rebuilt.

> Would you like me to proceed with cleaning the build cache?

**User:**
> Yes, go ahead.

**Claude:**
> Cleaning build cache...

*Claude uses: `docker_system_prune`*

```json
{
  "all": false,
  "volumes": false,
  "filters": {}
}
```

**Output:**
```json
{
  "containers_deleted": 0,
  "images_deleted": 0,
  "space_reclaimed_mb": 2048.9,
  "volumes_deleted": 0
}
```

**Claude:**
> Build cache cleared! Reclaimed an additional 2.0 GB.
>
> **Total Cleanup Results:**
> - Total space reclaimed: 5.7 GB
> - Build cache: Cleared
> - Running containers: All safe
> - Active images: Preserved

#### What's Happening

1. **Assessment** - Check disk usage with `system_df`
2. **List resources** - Identify what can be safely removed
3. **Selective cleanup** - Remove stopped containers first
4. **Image pruning** - Remove unused images
5. **Volume pruning** - Clean up unused volumes
6. **Build cache** - Optional aggressive cleanup
7. **Safety** - Never touch running containers or their dependencies

#### Key Takeaways

- Always assess before cleaning (`docker_system_df`)
- Clean in order: containers → images → volumes → cache
- Use filters to target specific resources
- `volumes: true` in container removal also cleans anonymous volumes
- Build cache cleanup affects future build performance
- Running containers and their dependencies are automatically protected

---

## 4. Troubleshooting Workflows

### Use Case: Using the Troubleshoot Prompt for a Crashing Application

An application container keeps crashing, and you need AI-powered diagnosis.

#### Conversation Example

**User:**
> My "payment-processor" container keeps crashing. Can you use the troubleshoot prompt to help diagnose it?

**Claude:**
> I'll use the troubleshoot prompt to analyze your container. This will gather comprehensive information about the container state, configuration, and logs.

*Claude uses prompt: `troubleshoot_container`*

```json
{
  "container_id": "payment-processor"
}
```

**Claude receives context:**
```
Container Information:
- ID: pay123
- Name: payment-processor
- Status: exited
- Image: payment-app:v2.1.0
- Running: False
- Exit Code: 137
- Error: None

Configuration:
- Command: ['python', 'app.py']
- Entrypoint: default
- Environment: 12 variables
- Restart Policy: on-failure

Recent Logs (last 50 lines):
2025-10-24T10:20:15.123Z [INFO] Payment processor starting...
2025-10-24T10:20:15.456Z [INFO] Connecting to database...
2025-10-24T10:20:16.789Z [INFO] Database connection established
2025-10-24T10:20:17.012Z [INFO] Loading payment providers...
2025-10-24T10:20:18.345Z [WARNING] High memory usage: 480MB
2025-10-24T10:20:19.678Z [WARNING] Memory pressure detected
2025-10-24T10:20:20.901Z [ERROR] Killed
```

**Claude:**
> I've analyzed your payment-processor container. Here's what I found:

> **Problem Identified:** The container is being killed by the OOM (Out of Memory) killer.

> **Evidence:**
> 1. Exit Code 137 - This specifically indicates the process was killed by SIGKILL, typically from the OOM killer
> 2. Logs show memory warnings before termination ("High memory usage", "Memory pressure")
> 3. Final error message: "Killed"

> **Root Cause:** The container is running out of memory. This can happen because:
> - Memory limit is too low for the application's needs
> - Memory leak in the application
> - Inefficient memory usage (large data loading)

> **Recommended Solutions:**

> 1. **Immediate fix:** Increase memory limit
>    - Current limit likely around 512MB
>    - Recommendation: Increase to 1GB or 2GB

> 2. **Investigate the application:**
>    - Check for memory leaks
>    - Review the "Loading payment providers" step - this might be loading too much data
>    - Consider lazy loading or pagination

> 3. **Add monitoring:**
>    - Set up memory usage alerts
>    - Add health checks

> Let me check the current memory limit:

*Claude uses: `docker_inspect_container`*

```json
{
  "container_id": "payment-processor"
}
```

**Output (excerpt):**
```json
{
  "details": {
    "HostConfig": {
      "Memory": 536870912
    }
  }
}
```

**Claude:**
> Confirmed! The container has a 512MB (536870912 bytes) memory limit, which is insufficient.

> **Action Plan:**
> 1. Stop and remove the current container
> 2. Recreate with increased memory (2GB)
> 3. Monitor memory usage after restart
> 4. If the issue persists, investigate application memory leaks

> Would you like me to recreate the container with increased memory?

**User:**
> Yes, please recreate it with 2GB memory and show me how to monitor it.

**Claude:**
> I'll recreate the container with better resource allocation.

*Claude uses: `docker_stop_container`*

```json
{
  "container_id": "payment-processor",
  "timeout": 10
}
```

*Claude uses: `docker_remove_container`*

```json
{
  "container_id": "payment-processor",
  "force": false,
  "volumes": false
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "payment-app:v2.1.0",
  "name": "payment-processor",
  "detach": true,
  "mem_limit": "2g",
  "mem_reservation": "1g",
  "restart_policy": {
    "Name": "on-failure",
    "MaximumRetryCount": 3
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "payment-processor"
}
```

**Claude:**
> Container recreated with 2GB memory limit. Now monitoring...

*Claude uses: `docker_container_stats`*

```json
{
  "container_id": "payment-processor",
  "stream": false
}
```

**Output:**
```json
{
  "memory_usage_mb": 645.2,
  "memory_limit_mb": 2048.0,
  "memory_percent": 31.5,
  "cpu_percent": 5.2
}
```

**Claude:**
> Perfect! The container is now running successfully:
> - Memory usage: 645MB / 2048MB (31.5%) - healthy headroom
> - CPU: 5.2% - normal
> - Status: Running

> **Monitoring Commands:**
> You can monitor this container with:
> ```
> docker stats payment-processor --no-stream  # One-time stats
> docker stats payment-processor             # Live monitoring
> ```

> Or ask me to check stats periodically. The container now has sufficient memory and should run stably.

#### What's Happening

1. **Prompt execution** - `troubleshoot_container` gathers container state, config, and logs
2. **AI analysis** - Claude analyzes exit code, logs, and patterns to diagnose OOM kill
3. **Investigation** - Verify diagnosis by inspecting current memory limit
4. **Solution** - Recreate container with appropriate resources
5. **Verification** - Monitor stats to ensure problem is resolved
6. **Documentation** - Provide ongoing monitoring guidance

#### Key Takeaways

- Exit code 137 = SIGKILL, often from OOM killer
- Troubleshoot prompt provides comprehensive context for diagnosis
- Memory limits should account for application peak usage
- Always verify fixes with stats monitoring
- Memory reservation (soft limit) helps with resource scheduling
- Restart policies prevent infinite restart loops

---

## 5. Multi-Container Applications

### Use Case: WordPress with MySQL and PhpMyAdmin

Deploy a complete WordPress stack with database management.

#### Conversation Example

**User:**
> I want to set up WordPress with MySQL and PhpMyAdmin for database management. Can you deploy this complete stack?

**Claude:**
> I'll deploy a complete WordPress stack for you. This will include:
> 1. MySQL database for WordPress data
> 2. WordPress application
> 3. PhpMyAdmin for database management
> 4. Custom network for secure communication
> 5. Persistent volumes for data

> Let me set this up step by step.

*Claude uses: `docker_create_network`*

```json
{
  "name": "wordpress-network",
  "driver": "bridge",
  "internal": false
}
```

**Output:**
```json
{
  "network_id": "net789...",
  "name": "wordpress-network"
}
```

*Claude uses: `docker_create_volume`*

```json
{
  "name": "mysql-data",
  "driver": "local"
}
```

*Claude uses: `docker_create_volume`*

```json
{
  "name": "wordpress-data",
  "driver": "local"
}
```

**Claude:**
> Network and volumes created. Deploying MySQL...

*Claude uses: `docker_pull_image`*

```json
{
  "image": "mysql:8.0"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "mysql:8.0",
  "name": "wordpress-mysql",
  "detach": true,
  "network": "wordpress-network",
  "environment": {
    "MYSQL_ROOT_PASSWORD": "secure_root_password_123",
    "MYSQL_DATABASE": "wordpress",
    "MYSQL_USER": "wordpress_user",
    "MYSQL_PASSWORD": "wordpress_pass_456"
  },
  "volumes": {
    "mysql-data": {
      "bind": "/var/lib/mysql",
      "mode": "rw"
    }
  },
  "mem_limit": "512m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "wordpress-mysql"
}
```

**Claude:**
> MySQL is starting. Let me wait a moment for it to initialize, then deploy WordPress...

*Claude uses: `docker_pull_image`*

```json
{
  "image": "wordpress:latest"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "wordpress:latest",
  "name": "wordpress-app",
  "detach": true,
  "network": "wordpress-network",
  "ports": {
    "80/tcp": 8080
  },
  "environment": {
    "WORDPRESS_DB_HOST": "wordpress-mysql:3306",
    "WORDPRESS_DB_USER": "wordpress_user",
    "WORDPRESS_DB_PASSWORD": "wordpress_pass_456",
    "WORDPRESS_DB_NAME": "wordpress"
  },
  "volumes": {
    "wordpress-data": {
      "bind": "/var/www/html",
      "mode": "rw"
    }
  },
  "mem_limit": "512m",
  "restart_policy": {
    "Name": "unless-stopped"
  },
  "depends_on": ["wordpress-mysql"]
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "wordpress-app"
}
```

**Claude:**
> WordPress deployed. Now adding PhpMyAdmin for database management...

*Claude uses: `docker_pull_image`*

```json
{
  "image": "phpmyadmin:latest"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "phpmyadmin:latest",
  "name": "wordpress-phpmyadmin",
  "detach": true,
  "network": "wordpress-network",
  "ports": {
    "80/tcp": 8081
  },
  "environment": {
    "PMA_HOST": "wordpress-mysql",
    "PMA_PORT": "3306",
    "MYSQL_ROOT_PASSWORD": "secure_root_password_123"
  },
  "mem_limit": "256m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "wordpress-phpmyadmin"
}
```

**Claude:**
> Perfect! Let me verify all containers are running...

*Claude uses: `docker_list_containers`*

```json
{
  "all": false,
  "filters": {
    "network": ["wordpress-network"]
  }
}
```

**Output:**
```json
{
  "containers": [
    {
      "name": "wordpress-mysql",
      "status": "running",
      "image": "mysql:8.0"
    },
    {
      "name": "wordpress-app",
      "status": "running",
      "image": "wordpress:latest"
    },
    {
      "name": "wordpress-phpmyadmin",
      "status": "running",
      "image": "phpmyadmin:latest"
    }
  ],
  "count": 3
}
```

**Claude:**
> Excellent! Your WordPress stack is fully deployed and running. Here's the complete setup:

> **Stack Components:**

> 1. **MySQL Database**
>    - Container: wordpress-mysql
>    - Network: wordpress-network (internal)
>    - Persistent storage: mysql-data volume
>    - Memory limit: 512MB

> 2. **WordPress Application**
>    - Container: wordpress-app
>    - URL: http://localhost:8080
>    - Connected to: wordpress-mysql
>    - Persistent storage: wordpress-data volume
>    - Memory limit: 512MB

> 3. **PhpMyAdmin**
>    - Container: wordpress-phpmyadmin
>    - URL: http://localhost:8081
>    - Connected to: wordpress-mysql
>    - Login: root / secure_root_password_123
>    - Memory limit: 256MB

> **Network Architecture:**
> - All containers communicate via wordpress-network
> - Only WordPress (8080) and PhpMyAdmin (8081) are exposed to host
> - MySQL is only accessible within the network (more secure)

> **Data Persistence:**
> - MySQL data is stored in the mysql-data volume
> - WordPress files are stored in the wordpress-data volume
> - Data persists even if containers are removed

> **Next Steps:**
> 1. Visit http://localhost:8080 to set up WordPress
> 2. Use http://localhost:8081 to manage the database
> 3. Complete WordPress installation wizard

> The stack is configured with restart policies, so it will automatically start when Docker starts.

#### What's Happening

1. **Network creation** - Isolated network for secure inter-container communication
2. **Volume creation** - Persistent storage for databases and files
3. **Sequential deployment** - MySQL first (dependency), then WordPress, then PhpMyAdmin
4. **Service discovery** - Containers reference each other by name (wordpress-mysql)
5. **Port mapping** - Only application ports exposed to host
6. **Resource limits** - Each service has appropriate memory limits
7. **Restart policies** - All containers restart automatically
8. **Verification** - List containers to confirm all services running

#### Key Takeaways

- Deploy dependencies (database) before dependent services
- Use custom networks for secure multi-container communication
- Named volumes provide data persistence
- Service discovery works automatically via container names
- Only expose necessary ports to host
- Set different memory limits based on service requirements
- Restart policies ensure stack stays running
- Network isolation keeps database internal (security)

---

## 6. Development Workflows

### Use Case: Hot Reload Development with Node.js

Set up a development environment with hot reload for rapid iteration.

#### Conversation Example

**User:**
> I'm developing a Node.js application. Can you help me set up a development container with hot reload so I don't have to rebuild every time I make changes?

**Claude:**
> I'll set up a development environment with hot reload using volume mounts. This allows your code changes to immediately reflect in the container without rebuilding.

> First, let me understand your project structure. Where is your Node.js project located?

**User:**
> It's in `/Users/dev/my-nodejs-app` and has a package.json with a "dev" script that uses nodemon.

**Claude:**
> Perfect! I'll create a development container with:
> 1. Volume mount for live code sync
> 2. Node.js with nodemon for auto-restart
> 3. Port mapping for accessing the app
> 4. Development environment variables

*Claude uses: `docker_pull_image`*

```json
{
  "image": "node:18-alpine"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "node:18-alpine",
  "name": "nodejs-dev",
  "detach": true,
  "command": ["npm", "run", "dev"],
  "working_dir": "/app",
  "volumes": {
    "/Users/dev/my-nodejs-app": {
      "bind": "/app",
      "mode": "rw"
    },
    "node_modules_cache": {
      "bind": "/app/node_modules",
      "mode": "rw"
    }
  },
  "ports": {
    "3000/tcp": 3000,
    "9229/tcp": 9229
  },
  "environment": {
    "NODE_ENV": "development",
    "DEBUG": "*"
  },
  "mem_limit": "1g"
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "nodejs-dev"
}
```

**Claude:**
> Container created, but it might fail if dependencies aren't installed. Let me check the logs...

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "nodejs-dev",
  "tail": 20,
  "follow": false
}
```

**Output:**
```json
{
  "logs": "npm ERR! Cannot find module 'express'\nnpm ERR! ...\n"
}
```

**Claude:**
> As expected, we need to install dependencies first. Let me do that:

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "nodejs-dev",
  "command": ["npm", "install"],
  "workdir": "/app"
}
```

**Output:**
```json
{
  "exit_code": 0,
  "output": "added 142 packages in 12s\n..."
}
```

**Claude:**
> Dependencies installed! Now restarting the application...

*Claude uses: `docker_restart_container`*

```json
{
  "container_id": "nodejs-dev"
}
```

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "nodejs-dev",
  "tail": 10,
  "follow": false
}
```

**Output:**
```json
{
  "logs": "[nodemon] starting `node index.js`\nServer listening on port 3000\n[nodemon] watching for file changes...\n"
}
```

**Claude:**
> Excellent! Your development environment is ready. Here's what's set up:

> **Development Container:**
> - Container: nodejs-dev
> - Node.js: v18 (Alpine)
> - Hot reload: nodemon watching for changes
> - Application URL: http://localhost:3000
> - Debugger port: 9229 (for VS Code debugging)

> **Volume Mounts:**
> 1. Project files: `/Users/dev/my-nodejs-app` → `/app`
>    - All your code changes sync immediately
> 2. node_modules: Separate named volume
>    - Prevents performance issues with node_modules
>    - Faster on Windows/Mac

> **How it works:**
> 1. Edit any file in `/Users/dev/my-nodejs-app`
> 2. nodemon detects the change automatically
> 3. Application restarts automatically
> 4. Changes visible at http://localhost:3000

> **VS Code Debugging:**
> Add this to your `.vscode/launch.json`:
> ```json
> {
>   "type": "node",
>   "request": "attach",
>   "name": "Attach to Docker",
>   "port": 9229,
>   "address": "localhost",
>   "localRoot": "${workspaceFolder}",
>   "remoteRoot": "/app"
> }
> ```

> Try making a change to your code - it should reload automatically!

**User:**
> Great! Can you show me the logs in real-time so I can see it working?

**Claude:**
> I'll show you the logs. You can also access them anytime using the container logs resource.

> **Container Logs Resource URI:**
> `container://logs/nodejs-dev`

> Let me fetch recent logs:

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "nodejs-dev",
  "tail": 30,
  "timestamps": true,
  "follow": false
}
```

**Output:**
```json
{
  "logs": "2025-10-24T10:30:15.123Z [nodemon] restarting due to changes...\n2025-10-24T10:30:15.456Z [nodemon] starting `node index.js`\n2025-10-24T10:30:15.789Z Server listening on port 3000\n2025-10-24T10:30:15.890Z Connected to database\n"
}
```

**Claude:**
> Your development environment is working perfectly! Here are some helpful commands:

> **Useful Operations:**
> 1. View logs: Ask me to check logs for nodejs-dev
> 2. Restart: If something gets stuck, I can restart the container
> 3. Exec commands: Run any npm command inside the container
> 4. Stats: Monitor resource usage during development

> **Tips:**
> - nodemon watches all files except node_modules
> - Source maps work correctly for debugging
> - Environment variables can be changed without rebuild
> - The node_modules volume persists across container restarts

> Happy coding! The container will keep running until you stop it.

#### What's Happening

1. **Image selection** - Choose appropriate base image (node:18-alpine)
2. **Volume mounting** - Mount source code for live sync
3. **Named volume** - Separate node_modules for performance
4. **Port mapping** - Application (3000) and debugger (9229)
5. **Dependency installation** - Install packages inside container
6. **Monitoring** - Check logs to verify hot reload works
7. **Debugging setup** - Expose debugger port for IDE integration

#### Key Takeaways

- Volume mounts enable hot reload without rebuilding
- Named volume for node_modules improves performance
- Expose debugger port for IDE integration
- Use nodemon/similar tools for auto-restart
- Development environment variables (NODE_ENV=development)
- Container logs show application output in real-time
- Exec command for running additional operations
- Source code stays on host, editable with any IDE

---

## 7. CI/CD Integration

### Use Case: Building and Testing in CI Pipeline

Simulate a CI/CD pipeline that builds, tests, and deploys a Docker image.

#### Conversation Example

**User:**
> I'm setting up a CI/CD pipeline. Can you show me how to build an image, run tests in a container, and then clean up if tests fail?

**Claude:**
> I'll demonstrate a complete CI/CD workflow using Docker tools. This simulates what would happen in a GitHub Actions or GitLab CI pipeline.

> **Pipeline Steps:**
> 1. Build the application image
> 2. Run unit tests in a container
> 3. Run integration tests
> 4. Tag image for registry (if tests pass)
> 5. Clean up test containers
> 6. Push to registry (simulated)

> Let me execute this pipeline:

**Claude:**
> **Step 1: Build Application Image**

*Claude uses: `docker_build_image`*

```json
{
  "path": "/Users/dev/my-app",
  "tag": "myapp:build-123",
  "dockerfile": "Dockerfile",
  "buildargs": {
    "BUILD_ENV": "ci",
    "VERSION": "1.2.3"
  },
  "target": "production"
}
```

**Output:**
```json
{
  "image_id": "sha256:abc123...",
  "tags": ["myapp:build-123"],
  "status": "Build successful"
}
```

**Claude:**
> Build successful! Image created: myapp:build-123

> **Step 2: Run Unit Tests**

*Claude uses: `docker_create_container`*

```json
{
  "image": "myapp:build-123",
  "name": "test-unit-123",
  "command": ["npm", "run", "test:unit"],
  "detach": false,
  "remove": true,
  "environment": {
    "NODE_ENV": "test",
    "CI": "true"
  }
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "test-unit-123"
}
```

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "test-unit-123",
  "tail": 100
}
```

**Output:**
```json
{
  "logs": "Running unit tests...\n  ✓ User authentication works\n  ✓ Data validation passes\n  ✓ API endpoints respond correctly\n\nTests passed: 45/45\nCoverage: 87%\n"
}
```

**Claude:**
> Unit tests passed! (45/45, 87% coverage)

> **Step 3: Run Integration Tests**

*Claude uses: `docker_create_network`*

```json
{
  "name": "test-network-123"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "postgres:15-alpine",
  "name": "test-db-123",
  "network": "test-network-123",
  "environment": {
    "POSTGRES_DB": "test_db",
    "POSTGRES_USER": "test_user",
    "POSTGRES_PASSWORD": "test_pass"
  },
  "detach": true
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "test-db-123"
}
```

**Claude:**
> Test database started. Running integration tests...

*Claude uses: `docker_create_container`*

```json
{
  "image": "myapp:build-123",
  "name": "test-integration-123",
  "network": "test-network-123",
  "command": ["npm", "run", "test:integration"],
  "environment": {
    "NODE_ENV": "test",
    "DATABASE_URL": "postgresql://test_user:test_pass@test-db-123:5432/test_db",
    "CI": "true"
  },
  "detach": false
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "test-integration-123"
}
```

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "test-integration-123",
  "tail": 50
}
```

**Output:**
```json
{
  "logs": "Running integration tests...\n  ✓ Database connection\n  ✓ User registration flow\n  ✓ Order processing\n  ✓ Payment integration\n\nTests passed: 12/12\n"
}
```

**Claude:**
> Integration tests passed! (12/12)

> **Step 4: Tag Image for Registry**

*Claude uses: `docker_tag_image`*

```json
{
  "source_image": "myapp:build-123",
  "target_image": "myregistry.com/myapp:1.2.3"
}
```

*Claude uses: `docker_tag_image`*

```json
{
  "source_image": "myapp:build-123",
  "target_image": "myregistry.com/myapp:latest"
}
```

**Output:**
```json
{
  "source": "myapp:build-123",
  "target": "myregistry.com/myapp:latest",
  "status": "Tagged successfully"
}
```

**Claude:**
> Image tagged for production:
> - myregistry.com/myapp:1.2.3
> - myregistry.com/myapp:latest

> **Step 5: Clean Up Test Resources**

*Claude uses: `docker_stop_container`*

```json
{
  "container_id": "test-db-123",
  "timeout": 5
}
```

*Claude uses: `docker_remove_container`*

```json
{
  "container_id": "test-db-123",
  "force": true,
  "volumes": true
}
```

*Claude uses: `docker_remove_network`*

```json
{
  "network_id": "test-network-123"
}
```

**Claude:**
> Test resources cleaned up.

> **Step 6: Push to Registry (Simulated)**

> In a real CI/CD environment, you would now push:

*Claude shows what would be done:*
```json
{
  "tool": "docker_push_image",
  "arguments": {
    "image": "myregistry.com/myapp:1.2.3",
    "auth": {
      "username": "${REGISTRY_USER}",
      "password": "${REGISTRY_PASSWORD}"
    }
  }
}
```

**Claude:**
> **CI/CD Pipeline Results:**

> ✓ Build: SUCCESS (myapp:build-123)
> ✓ Unit Tests: PASSED (45/45, 87% coverage)
> ✓ Integration Tests: PASSED (12/12)
> ✓ Image Tagged: myregistry.com/myapp:1.2.3
> ✓ Cleanup: COMPLETE

> **Pipeline Summary:**
> - Build Time: ~45 seconds
> - Test Time: ~2 minutes
> - Total Time: ~2.75 minutes
> - Status: READY FOR DEPLOYMENT

> **Next Steps in Production CI/CD:**
> 1. Push image to registry
> 2. Deploy to staging environment
> 3. Run smoke tests
> 4. Deploy to production with blue-green strategy

> **Failure Handling:**
> If any test had failed, I would:
> 1. Stop all test containers immediately
> 2. Clean up test network and volumes
> 3. Remove the build image (don't tag or push)
> 4. Report detailed error logs
> 5. Exit with non-zero code

**User:**
> Can you show me what happens when tests fail?

**Claude:**
> I'll simulate a test failure scenario:

*Claude simulates: `docker_start_container` (test-unit-123)*

**Simulated Output:**
```json
{
  "logs": "Running unit tests...\n  ✓ User authentication works\n  ✗ Data validation fails\n     Expected: valid, Received: invalid\n\nTests passed: 44/45\nTests failed: 1\n"
}
```

**Claude:**
> Test failed! Here's the failure handling:

> **Failure Detected:**
> - Test: Data validation
> - Status: FAILED (44/45 passed)

> **Cleanup Actions:**

*Claude uses: `docker_stop_container` (all test containers)*
*Claude uses: `docker_remove_container` (all test containers)*
*Claude uses: `docker_remove_network` (test-network-123)*
*Claude uses: `docker_remove_image`*

```json
{
  "image_id": "myapp:build-123",
  "force": true
}
```

**Claude:**
> **Pipeline Results:**

> ✓ Build: SUCCESS
> ✗ Unit Tests: FAILED (44/45)
> ⊘ Integration Tests: SKIPPED (due to unit test failure)
> ⊘ Image Tagging: SKIPPED
> ⊘ Registry Push: SKIPPED
> ✓ Cleanup: COMPLETE

> **Actions Taken:**
> 1. Stopped all test containers
> 2. Removed test network
> 3. Deleted build image (myapp:build-123)
> 4. Captured failure logs

> **Failure Details:**
> ```
> Test: Data validation
> File: tests/validation.test.js
> Error: Expected valid data, received invalid
> ```

> The pipeline would exit with code 1, preventing any deployment.
> No resources were left behind - complete cleanup performed.

#### What's Happening

1. **Image build** - Build application with CI-specific tags and args
2. **Unit testing** - Run fast, isolated unit tests first
3. **Integration testing** - Set up test database and run integration tests
4. **Conditional tagging** - Only tag images if all tests pass
5. **Cleanup** - Always clean up test resources, even on failure
6. **Registry push** - Final step to publish validated image
7. **Failure handling** - Stop pipeline and clean up on any failure

#### Key Takeaways

- Build images with unique tags (build numbers)
- Run unit tests before integration tests (fail fast)
- Use temporary networks for test isolation
- Clean up test resources in all scenarios (success or failure)
- Only tag and push images after all tests pass
- Use `remove: true` for ephemeral test containers
- Capture logs for debugging failed tests
- Tag images with both version and 'latest'
- Simulate real CI/CD environment with environment variables

---

## 8. Resource Monitoring

### Use Case: Monitoring Container Resource Usage Over Time

Track resource usage to identify memory leaks or performance issues.

#### Conversation Example

**User:**
> I suspect my "payment-api" container has a memory leak. Can you help me monitor its resource usage over time?

**Claude:**
> I'll help you monitor the payment-api container for resource issues. Let me start by getting a baseline reading.

*Claude uses: `docker_container_stats`*

```json
{
  "container_id": "payment-api",
  "stream": false
}
```

**Output (Reading 1 - T=0):**
```json
{
  "container_id": "payment-api",
  "memory_usage_mb": 256.3,
  "memory_limit_mb": 1024.0,
  "memory_percent": 25.0,
  "cpu_percent": 3.2,
  "network_rx_mb": 15.4,
  "network_tx_mb": 8.7,
  "block_io_read_mb": 12.3,
  "block_io_write_mb": 5.1
}
```

**Claude:**
> Baseline reading captured. I'll monitor this container over time to detect any trends.
>
> **Initial State:**
> - Memory: 256 MB / 1024 MB (25%)
> - CPU: 3.2%
> - Network: 15.4 MB in / 8.7 MB out

> Let me check again in a moment to establish a trend...

*[Time passes - simulated]*

*Claude uses: `docker_container_stats` (Reading 2 - T=5min)*

**Output (Reading 2 - T=5min):**
```json
{
  "memory_usage_mb": 312.8,
  "memory_limit_mb": 1024.0,
  "memory_percent": 30.5,
  "cpu_percent": 4.1
}
```

*Claude uses: `docker_container_stats` (Reading 3 - T=10min)*

**Output (Reading 3 - T=10min):**
```json
{
  "memory_usage_mb": 387.2,
  "memory_limit_mb": 1024.0,
  "memory_percent": 37.8,
  "cpu_percent": 3.9
}
```

*Claude uses: `docker_container_stats` (Reading 4 - T=15min)*

**Output (Reading 4 - T=15min):**
```json
{
  "memory_usage_mb": 468.5,
  "memory_limit_mb": 1024.0,
  "memory_percent": 45.8,
  "cpu_percent": 4.2
}
```

**Claude:**
> I'm detecting a concerning pattern. Let me collect more data and analyze...

*Claude uses: `docker_container_stats` (Reading 5 - T=20min)*

**Output (Reading 5 - T=20min):**
```json
{
  "memory_usage_mb": 542.1,
  "memory_limit_mb": 1024.0,
  "memory_percent": 52.9,
  "cpu_percent": 3.8
}
```

**Claude:**
> **Memory Leak Detected!**

> **Analysis:**
> ```
> Time    Memory (MB)  Memory %  Change    Rate
> ------------------------------------------------
> T=0     256.3        25.0%     -         -
> T=5     312.8        30.5%     +56.5 MB  +11.3 MB/min
> T=10    387.2        37.8%     +74.4 MB  +14.9 MB/min
> T=15    468.5        45.8%     +81.3 MB  +16.3 MB/min
> T=20    542.1        52.9%     +73.6 MB  +14.7 MB/min
>
> Average Growth: ~14 MB/minute
> ```

> **Conclusions:**
> 1. **Memory is growing steadily** - Not normal for a stable application
> 2. **Growth rate is consistent** - ~14 MB/minute suggests a leak
> 3. **CPU is stable** - Rules out CPU-bound memory growth
> 4. **Projected limit hit** - Will reach 1GB limit in ~35 minutes

> **Immediate Actions Needed:**
> 1. Capture heap dump for analysis
> 2. Check application logs for errors
> 3. Review recent code changes
> 4. Plan for container restart

> Let me check the logs for clues:

*Claude uses: `docker_container_logs`*

```json
{
  "container_id": "payment-api",
  "tail": 50,
  "timestamps": true
}
```

**Output:**
```json
{
  "logs": "2025-10-24T10:00:15.123Z [INFO] Processing payment batch\n2025-10-24T10:00:16.456Z [WARNING] Cache size: 15234 entries\n2025-10-24T10:05:20.789Z [WARNING] Cache size: 18932 entries\n2025-10-24T10:10:25.012Z [WARNING] Cache size: 22847 entries\n2025-10-24T10:15:30.345Z [WARNING] Cache size: 26534 entries\n..."
}
```

**Claude:**
> Found it! The cache is growing unbounded.

> **Root Cause Identified:**
> - Application cache is growing without limits
> - Cache entries are not being evicted
> - Cache size correlates with memory growth

> **Recommended Fixes:**
> 1. Implement cache size limit (e.g., LRU with max 10,000 entries)
> 2. Add TTL (time-to-live) for cache entries
> 3. Consider using Redis for caching (external, with eviction policies)

> **Immediate Mitigation:**
> Would you like me to restart the container to free memory while you implement a fix?

**User:**
> Yes, please restart it. But first, can you set up monitoring to alert me if this happens again?

**Claude:**
> I'll restart the container and show you how to set up ongoing monitoring.

*Claude uses: `docker_restart_container`*

```json
{
  "container_id": "payment-api",
  "timeout": 10
}
```

**Claude:**
> Container restarted. Memory is now reset. Here's how to monitor going forward:

> **Option 1: Use Container Stats Resource**
> You can access stats via the resource URI:
> ```
> container://stats/payment-api
> ```

> **Option 2: Periodic Monitoring Script**
> I can provide a monitoring approach:
>
> 1. Check stats every 5 minutes
> 2. Alert if memory growth exceeds 10 MB/minute
> 3. Alert if memory exceeds 80% of limit
> 4. Log all readings for analysis

> **Option 3: External Monitoring**
> Consider using:
> - Prometheus + cAdvisor for metrics collection
> - Grafana for visualization
> - Alert rules for threshold breaches

> **Current Status:**

*Claude uses: `docker_container_stats`*

```json
{
  "container_id": "payment-api",
  "stream": false
}
```

**Output:**
```json
{
  "memory_usage_mb": 142.5,
  "memory_limit_mb": 1024.0,
  "memory_percent": 13.9,
  "cpu_percent": 8.1
}
```

**Claude:**
> Memory reset to 142 MB (13.9%) - back to normal startup levels.
> CPU is slightly elevated (8.1%) due to application initialization.

> **Action Items:**
> 1. Fix the cache issue in your application code
> 2. Add cache size limits and TTL
> 3. Set up proper monitoring
> 4. Consider adding a health check that fails if memory is too high

> I can help you implement any of these solutions!

#### What's Happening

1. **Baseline measurement** - Take initial resource reading
2. **Periodic sampling** - Check stats at regular intervals
3. **Trend analysis** - Calculate growth rates and patterns
4. **Correlation** - Check logs for related events
5. **Root cause identification** - Match memory growth to log patterns
6. **Mitigation** - Restart container to free memory
7. **Prevention** - Recommend monitoring and code fixes

#### Key Takeaways

- Periodic sampling reveals trends that single readings miss
- Memory growth rate (MB/min) is more important than absolute value
- Correlate stats with logs for root cause analysis
- Stable CPU + growing memory = likely memory leak
- Project time-to-failure based on growth rate
- Restart is temporary fix - code change needed
- Set up monitoring to prevent recurrence
- Container stats resource URI enables automated monitoring

---

## 9. Network Configuration

### Use Case: Multi-Tier Application with Network Isolation

Set up a three-tier application (frontend, backend, database) with proper network segmentation.

#### Conversation Example

**User:**
> I need to deploy a three-tier application with proper network isolation:
> - Frontend (React) should be publicly accessible
> - Backend (API) should only be accessible to frontend
> - Database should only be accessible to backend
>
> Can you set this up with proper network security?

**Claude:**
> I'll set up a secure three-tier architecture with network isolation. This follows security best practices where each tier only accesses what it needs.

> **Architecture:**
> ```
> Internet → Frontend (public) → Backend (internal) → Database (internal)
> ```

> **Network Design:**
> 1. **frontend-network** - Public facing
> 2. **backend-network** - Internal, frontend + backend
> 3. **database-network** - Internal, backend + database only

> Let me create this infrastructure:

**Claude:**
> **Step 1: Create Networks**

*Claude uses: `docker_create_network`*

```json
{
  "name": "frontend-network",
  "driver": "bridge",
  "internal": false
}
```

*Claude uses: `docker_create_network`*

```json
{
  "name": "backend-network",
  "driver": "bridge",
  "internal": true
}
```

*Claude uses: `docker_create_network`*

```json
{
  "name": "database-network",
  "driver": "bridge",
  "internal": true
}
```

**Output:**
```json
{
  "network_id": "net_front123",
  "name": "frontend-network",
  "driver": "bridge",
  "internal": false
}
```

**Claude:**
> Networks created with isolation:
> - frontend-network: External access allowed
> - backend-network: Internal only (no external routing)
> - database-network: Internal only (no external routing)

> **Step 2: Deploy Database Tier**

*Claude uses: `docker_pull_image`*

```json
{
  "image": "postgres:15-alpine"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "postgres:15-alpine",
  "name": "app-database",
  "detach": true,
  "environment": {
    "POSTGRES_DB": "appdb",
    "POSTGRES_USER": "appuser",
    "POSTGRES_PASSWORD": "secure_db_password"
  },
  "volumes": {
    "postgres-data": {
      "bind": "/var/lib/postgresql/data",
      "mode": "rw"
    }
  },
  "mem_limit": "512m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_connect_container`*

```json
{
  "container_id": "app-database",
  "network": "database-network"
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "app-database"
}
```

**Claude:**
> Database deployed on database-network (isolated).

> **Step 3: Deploy Backend Tier**

*Claude uses: `docker_pull_image`*

```json
{
  "image": "mycompany/api:latest"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "mycompany/api:latest",
  "name": "app-backend",
  "detach": true,
  "environment": {
    "DATABASE_HOST": "app-database",
    "DATABASE_PORT": "5432",
    "DATABASE_NAME": "appdb",
    "DATABASE_USER": "appuser",
    "DATABASE_PASSWORD": "secure_db_password",
    "API_PORT": "8000"
  },
  "mem_limit": "1g",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

**Claude:**
> Backend created. Now connecting to both networks (backend and database):

*Claude uses: `docker_connect_container`*

```json
{
  "container_id": "app-backend",
  "network": "backend-network"
}
```

*Claude uses: `docker_connect_container`*

```json
{
  "container_id": "app-backend",
  "network": "database-network"
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "app-backend"
}
```

**Claude:**
> Backend deployed on both backend-network and database-network.
> - Can reach database via database-network
> - Can be reached by frontend via backend-network

> **Step 4: Deploy Frontend Tier**

*Claude uses: `docker_pull_image`*

```json
{
  "image": "mycompany/frontend:latest"
}
```

*Claude uses: `docker_create_container`*

```json
{
  "image": "mycompany/frontend:latest",
  "name": "app-frontend",
  "detach": true,
  "ports": {
    "80/tcp": 80,
    "443/tcp": 443
  },
  "environment": {
    "API_URL": "http://app-backend:8000",
    "NODE_ENV": "production"
  },
  "mem_limit": "512m",
  "restart_policy": {
    "Name": "unless-stopped"
  }
}
```

*Claude uses: `docker_connect_container`*

```json
{
  "container_id": "app-frontend",
  "network": "frontend-network"
}
```

*Claude uses: `docker_connect_container`*

```json
{
  "container_id": "app-frontend",
  "network": "backend-network"
}
```

*Claude uses: `docker_start_container`*

```json
{
  "container_id": "app-frontend"
}
```

**Claude:**
> Frontend deployed!
> - Connected to frontend-network (public)
> - Connected to backend-network (to reach API)
> - Port 80/443 exposed to host

> **Step 5: Verify Network Configuration**

*Claude uses: `docker_list_networks`*

```json
{
  "filters": {
    "name": ["frontend-network", "backend-network", "database-network"]
  }
}
```

**Output:**
```json
{
  "networks": [
    {
      "name": "frontend-network",
      "id": "net_front123",
      "driver": "bridge",
      "containers": ["app-frontend"]
    },
    {
      "name": "backend-network",
      "id": "net_back456",
      "driver": "bridge",
      "containers": ["app-frontend", "app-backend"]
    },
    {
      "name": "database-network",
      "id": "net_db789",
      "driver": "bridge",
      "containers": ["app-backend", "app-database"]
    }
  ]
}
```

*Claude uses: `docker_inspect_network`*

```json
{
  "network_id": "backend-network"
}
```

**Output:**
```json
{
  "details": {
    "Name": "backend-network",
    "Driver": "bridge",
    "Internal": true,
    "Containers": {
      "app-frontend": {
        "IPv4Address": "172.20.0.2/16"
      },
      "app-backend": {
        "IPv4Address": "172.20.0.3/16"
      }
    }
  }
}
```

**Claude:**
> Perfect! Network isolation is configured correctly. Let me verify connectivity:

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "app-frontend",
  "command": ["wget", "-O-", "http://app-backend:8000/health"]
}
```

**Output:**
```json
{
  "exit_code": 0,
  "output": "{\"status\": \"healthy\", \"database\": \"connected\"}"
}
```

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "app-frontend",
  "command": ["ping", "-c", "1", "app-database"]
}
```

**Output:**
```json
{
  "exit_code": 1,
  "output": "ping: app-database: Name or service not known"
}
```

**Claude:**
> Excellent! Network security is working as designed:
> ✓ Frontend CAN reach backend
> ✓ Frontend CANNOT reach database (blocked)

> **Deployment Complete!**

> **Network Topology:**
> ```
>                    [Internet]
>                        ↓
>         ┌──────────────────────────┐
>         │   Frontend (React)       │ ← Public (ports 80/443)
>         │   app-frontend           │
>         └──────────────────────────┘
>            ↓ backend-network only
>         ┌──────────────────────────┐
>         │   Backend (API)          │ ← Internal only
>         │   app-backend            │
>         └──────────────────────────┘
>            ↓ database-network only
>         ┌──────────────────────────┐
>         │   Database (PostgreSQL)  │ ← Internal only
>         │   app-database           │
>         └──────────────────────────┘
> ```

> **Security Configuration:**
>
> | Component | Networks | Accessible From | Exposed Ports |
> |-----------|----------|-----------------|---------------|
> | Frontend | frontend-network, backend-network | Internet | 80, 443 |
> | Backend | backend-network, database-network | Frontend only | None |
> | Database | database-network | Backend only | None |

> **Access Control:**
> - ✓ Internet can access Frontend
> - ✓ Frontend can access Backend
> - ✓ Backend can access Database
> - ✗ Frontend CANNOT access Database (security layer)
> - ✗ Internet CANNOT access Backend directly
> - ✗ Internet CANNOT access Database directly

> **Service Discovery:**
> - Frontend reaches backend via: `http://app-backend:8000`
> - Backend reaches database via: `app-database:5432`
> - DNS resolution works automatically within networks

> **Application URLs:**
> - Frontend: http://localhost (public)
> - Backend API: Only accessible via frontend
> - Database: Only accessible via backend

> The architecture follows security best practices with proper network segmentation!

**User:**
> This is great! Can you show me how to test the network isolation is actually working?

**Claude:**
> I'll run comprehensive network isolation tests to verify security.

**Claude:**
> **Test 1: Frontend to Backend (Should Succeed)**

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "app-frontend",
  "command": ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://app-backend:8000/health"]
}
```

**Output:**
```json
{
  "exit_code": 0,
  "output": "200"
}
```

**Claude:**
> ✓ Test 1 PASSED: Frontend successfully reached backend (HTTP 200)

> **Test 2: Frontend to Database (Should Fail)**

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "app-frontend",
  "command": ["nc", "-zv", "app-database", "5432"]
}
```

**Output:**
```json
{
  "exit_code": 1,
  "output": "nc: getaddrinfo: Name or service not known"
}
```

**Claude:**
> ✓ Test 2 PASSED: Frontend CANNOT reach database (isolation working)

> **Test 3: Backend to Database (Should Succeed)**

*Claude uses: `docker_exec_command`*

```json
{
  "container_id": "app-backend",
  "command": ["pg_isready", "-h", "app-database", "-p", "5432", "-U", "appuser"]
}
```

**Output:**
```json
{
  "exit_code": 0,
  "output": "app-database:5432 - accepting connections"
}
```

**Claude:**
> ✓ Test 3 PASSED: Backend successfully connected to database

> **Test 4: External Access to Backend (Should Fail)**

*Claude uses: `docker_inspect_container`*

```json
{
  "container_id": "app-backend"
}
```

**Output (excerpt):**
```json
{
  "details": {
    "NetworkSettings": {
      "Ports": {}
    }
  }
}
```

**Claude:**
> ✓ Test 4 PASSED: Backend has no exposed ports (cannot be accessed externally)

> **Test 5: External Access to Database (Should Fail)**

*Claude uses: `docker_inspect_container`*

```json
{
  "container_id": "app-database"
}
```

**Output (excerpt):**
```json
{
  "details": {
    "NetworkSettings": {
      "Ports": {}
    }
  }
}
```

**Claude:**
> ✓ Test 5 PASSED: Database has no exposed ports (cannot be accessed externally)

> **Security Test Summary:**
>
> | Test | Source | Target | Expected | Result |
> |------|--------|--------|----------|--------|
> | 1 | Frontend | Backend | Success | ✓ PASS |
> | 2 | Frontend | Database | Fail | ✓ PASS |
> | 3 | Backend | Database | Success | ✓ PASS |
> | 4 | External | Backend | Fail | ✓ PASS |
> | 5 | External | Database | Fail | ✓ PASS |

> **All security tests passed!** Network isolation is properly configured.

> **Additional Security Recommendations:**
> 1. Add firewall rules for additional protection
> 2. Use encrypted connections (TLS) between tiers
> 3. Implement authentication tokens for API access
> 4. Enable Docker content trust for image verification
> 5. Use secrets management for sensitive data
> 6. Regular security audits of network configuration

#### What's Happening

1. **Network creation** - Create separate networks for each tier
2. **Internal networks** - Mark backend/database networks as internal
3. **Database deployment** - Deploy only on database-network
4. **Backend deployment** - Connect to both backend and database networks
5. **Frontend deployment** - Connect to both frontend and backend networks
6. **Port exposure** - Only frontend exposes ports to host
7. **Verification** - Test connectivity matches security requirements
8. **Security testing** - Confirm isolation blocks unauthorized access

#### Key Takeaways

- Multiple network connections enable controlled access
- Internal networks prevent external routing
- Only frontend should expose ports to host
- Service discovery works within shared networks
- Name resolution only works on shared networks
- Test network isolation to verify security
- Each tier should only access what it needs
- Network segmentation is defense-in-depth strategy
- Use exec commands to test connectivity from inside containers
- Inspect network details to verify container membership

---

## Conclusion

These examples demonstrate real-world usage patterns for the Docker MCP Server through Claude. Key principles that apply across all scenarios:

1. **Safety First** - Always verify state before making changes
2. **Incremental Approach** - Break complex tasks into steps
3. **Verification** - Check results after each operation
4. **Cleanup** - Remove temporary resources
5. **Monitoring** - Track resource usage and health
6. **Security** - Use network isolation and minimal exposure
7. **Documentation** - Claude provides clear explanations
8. **Error Handling** - Diagnose issues with logs and stats

For more information:
- [API Reference](API.md) - Complete tool documentation
- [Setup Guide](SETUP.md) - Installation and configuration
- [Architecture](ARCHITECTURE.md) - System design details

---

**Questions or Issues?**
- GitHub Issues: https://github.com/williajm/mcp_docker/issues
- GitHub Discussions: https://github.com/williajm/mcp_docker/discussions
