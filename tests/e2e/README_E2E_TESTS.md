# E2E Tests

The current E2E suite focuses on stdio protocol robustness for the local MCP Docker server.

```bash
uv run pytest tests/e2e/ -v -m e2e
```

The server no longer exposes HTTP transport, prompts, resources, or destructive Docker tools, so the E2E suite does not cover network authentication, rate limiting, audit logging, or destructive-operation gating.
