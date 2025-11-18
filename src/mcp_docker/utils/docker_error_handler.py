"""Docker error handling utilities.

This module provides decorators and helpers for consistent Docker error handling
across all tool implementations, reducing boilerplate and ensuring consistent
error messages and logging.
"""

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from docker.errors import APIError
from docker.errors import ImageNotFound as DockerImageNotFound
from docker.errors import NotFound as DockerNotFound

from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    ImageNotFound,
    NetworkNotFound,
    VolumeNotFound,
)
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import (
    ERROR_CONTAINER_NOT_FOUND,
    ERROR_IMAGE_NOT_FOUND,
    ERROR_NETWORK_NOT_FOUND,
    ERROR_VOLUME_NOT_FOUND,
)

logger = get_logger(__name__)

# Type variable for decorator return type
F = TypeVar("F", bound=Callable[..., Any])


def handle_docker_errors(
    resource: str,
    operation: str,
    resource_id_param: str = "container_id",
) -> Callable[[F], F]:
    """Decorator that handles Docker API errors consistently.

    Maps docker.errors exceptions to custom MCP Docker exceptions with
    consistent logging and error messages.

    Args:
        resource: Type of resource ("container", "image", "network", "volume")
        operation: Operation being performed (for error messages)
        resource_id_param: Parameter name containing the resource ID (default: "container_id")

    Returns:
        Decorated function with error handling

    Example:
        @handle_docker_errors(resource="container", operation="start")
        async def start_container(container_id: str) -> dict:
            # Docker API calls here
            container.start()
            return {"status": "started"}

    Raises:
        ContainerNotFound: If container resource not found
        ImageNotFound: If image resource not found
        NetworkNotFound: If network resource not found
        VolumeNotFound: If volume resource not found
        DockerOperationError: For all other Docker API errors
    """
    # Map resource types to (exception class, error message template)
    error_map = {
        "container": (ContainerNotFound, ERROR_CONTAINER_NOT_FOUND),
        "image": (ImageNotFound, ERROR_IMAGE_NOT_FOUND),
        "network": (NetworkNotFound, ERROR_NETWORK_NOT_FOUND),
        "volume": (VolumeNotFound, ERROR_VOLUME_NOT_FOUND),
    }

    if resource not in error_map:
        valid_resources = list(error_map.keys())
        raise ValueError(f"Unknown resource type: {resource}. Must be one of {valid_resources}")

    not_found_exception, not_found_message = error_map[resource]

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except (DockerNotFound, DockerImageNotFound) as e:
                # Extract resource ID from kwargs or positional args
                resource_id = kwargs.get(resource_id_param)
                if resource_id is None and args:
                    # Try first positional argument
                    resource_id = args[0] if args else "unknown"

                error_msg = not_found_message.format(resource_id)
                logger.error(f"{resource.capitalize()} not found: {resource_id}")
                raise not_found_exception(error_msg) from e

            except APIError as e:
                # Extract resource ID for logging
                resource_id = kwargs.get(resource_id_param, "unknown")
                if resource_id == "unknown" and args:
                    resource_id = args[0] if args else "unknown"

                error_msg = f"Failed to {operation} {resource} {resource_id}: {e}"
                logger.error(error_msg)
                raise DockerOperationError(error_msg) from e

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except (DockerNotFound, DockerImageNotFound) as e:
                # Extract resource ID from kwargs or positional args
                resource_id = kwargs.get(resource_id_param)
                if resource_id is None and args:
                    resource_id = args[0] if args else "unknown"

                error_msg = not_found_message.format(resource_id)
                logger.error(f"{resource.capitalize()} not found: {resource_id}")
                raise not_found_exception(error_msg) from e

            except APIError as e:
                # Extract resource ID for logging
                resource_id = kwargs.get(resource_id_param, "unknown")
                if resource_id == "unknown" and args:
                    resource_id = args[0] if args else "unknown"

                error_msg = f"Failed to {operation} {resource} {resource_id}: {e}"
                logger.error(error_msg)
                raise DockerOperationError(error_msg) from e

        # Return appropriate wrapper based on whether function is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


__all__ = ["handle_docker_errors"]
