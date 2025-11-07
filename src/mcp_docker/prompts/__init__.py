"""MCP Prompts for Docker operations."""

from mcp_docker.prompts.templates import (
    DebugNetworkingPrompt,
    GenerateComposePrompt,
    OptimizeContainerPrompt,
    PromptProvider,
    SecurityAuditPrompt,
    TroubleshootContainerPrompt,
)

__all__ = [
    "DebugNetworkingPrompt",
    "GenerateComposePrompt",
    "OptimizeContainerPrompt",
    "PromptProvider",
    "SecurityAuditPrompt",
    "TroubleshootContainerPrompt",
]
