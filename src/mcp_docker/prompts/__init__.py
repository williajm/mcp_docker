"""MCP Prompts for Docker operations."""

from mcp_docker.prompts.templates import (
    GenerateComposePrompt,
    OptimizeContainerPrompt,
    PromptProvider,
    TroubleshootContainerPrompt,
)

__all__ = [
    "GenerateComposePrompt",
    "OptimizeContainerPrompt",
    "PromptProvider",
    "TroubleshootContainerPrompt",
]
