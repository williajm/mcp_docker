"""Logging configuration using loguru."""

import sys
from pathlib import Path
from typing import Any

from loguru import logger

from mcp_docker.config import ServerConfig


def setup_logger(config: ServerConfig, log_file: Path | None = None) -> None:
    """Configure loguru logger with project settings.

    Supports both human-readable (default) and JSON structured logging.
    JSON logging is recommended for production/SIEM integration.

    Args:
        config: Server configuration
        log_file: Optional path to log file

    """
    # Remove default handler
    logger.remove()

    if config.json_logging:
        # JSON structured logging for production/SIEM
        # SECURITY: Uses loguru's built-in serialization (battle-tested)
        logger.add(
            sys.stderr,
            level=config.log_level,
            serialize=True,  # JSON output
            backtrace=True,
            diagnose=False,  # Don't expose internals in production
        )

        if log_file:
            logger.add(
                log_file,
                level=config.log_level,
                serialize=True,  # JSON output
                rotation="10 MB",
                retention="7 days",
                compression="zip",
                backtrace=True,
                diagnose=False,
            )
    else:
        # Human-readable logging for development
        logger.add(
            sys.stderr,
            format=config.log_format,
            level=config.log_level,
            colorize=True,
            backtrace=True,
            diagnose=True,
        )

        if log_file:
            logger.add(
                log_file,
                format=config.log_format,
                level=config.log_level,
                rotation="10 MB",
                retention="7 days",
                compression="zip",
                backtrace=True,
                diagnose=True,
            )

    logger.info(f"Logger initialized with level: {config.log_level}")
    logger.info(f"JSON logging: {'enabled' if config.json_logging else 'disabled'}")
    if log_file:
        logger.info(f"Logging to file: {log_file}")


def get_logger(name: str | None = None) -> Any:  # noqa: ARG001
    """Get a logger instance.

    Args:
        name: Optional module name (for compatibility, not used by loguru)

    Returns:
        Loguru logger instance

    """
    return logger
