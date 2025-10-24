"""Logging configuration using loguru."""

import sys
from pathlib import Path

from loguru import logger

from mcp_docker.config import ServerConfig


def setup_logger(config: ServerConfig, log_file: Path | None = None) -> None:
    """Configure loguru logger with project settings.

    Args:
        config: Server configuration
        log_file: Optional path to log file

    """
    # Remove default handler
    logger.remove()

    # Add console handler with custom format
    logger.add(
        sys.stderr,
        format=config.log_format,
        level=config.log_level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # Add file handler if specified
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
    if log_file:
        logger.info(f"Logging to file: {log_file}")
