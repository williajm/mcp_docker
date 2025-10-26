# Docker Compose Test Files

This directory contains sample Docker Compose files for testing the MCP Docker Compose functionality.

## Sample Files

### nginx-redis.yml
Simple multi-service setup with:
- Nginx web server (port 8080)
- Redis cache (port 6379)
- Custom network
- Health checks

**Usage:**
```bash
docker compose -f compose_files/nginx-redis.yml up -d
docker compose -f compose_files/nginx-redis.yml ps
docker compose -f compose_files/nginx-redis.yml down
```

### postgres-pgadmin.yml
Database stack with:
- PostgreSQL 15 database (port 5432)
- pgAdmin web interface (port 5050)
- Persistent volume for database data
- Service dependencies

**Default credentials:**
- PostgreSQL: testuser/testpass (database: testdb)
- pgAdmin: admin@example.com/admin

### simple-webapp.yml
Minimal single-service example:
- Apache web server (port 8081)
- Volume mount for static content
- Auto-restart policy

## Security Notes

Files in this directory are used for testing and development only. When using the `docker_compose_write_file` tool:

- Files can only be written to this `compose_files/` directory
- All compose files are validated before execution
- Dangerous volume mounts (/, /etc, etc.) are blocked
- Port ranges are validated
- Service and project names are sanitized

## User-Generated Files

Claude can create custom compose files in this directory using the `docker_compose_write_file` tool. These files are automatically:
1. Validated for YAML syntax
2. Checked for security risks
3. Restricted to safe mount paths
4. Verified for valid port mappings

User-generated files will be prefixed with `user-` to distinguish them from samples.
