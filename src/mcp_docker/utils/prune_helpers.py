"""Helper functions for Docker prune operations.

This module provides shared utilities for prune operations across multiple tools,
reducing code duplication and maintaining consistency.
"""

from typing import Any

from docker.errors import APIError, DockerException

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def force_remove_all_images(docker_client: Any) -> tuple[list[dict[str, Any]], int]:
    """Remove ALL images forcefully, regardless of tags or usage.

    This is an extremely destructive operation that removes every single image,
    including tagged images and those in use by containers. Filters are not
    applicable in force_all mode as all images are targeted.

    Args:
        docker_client: Docker client instance

    Returns:
        Tuple of (deleted_images, space_reclaimed)
            - deleted_images: List of dicts with 'Deleted' keys containing image IDs
            - space_reclaimed: Total bytes freed
    """
    logger.warning("force_all=True: Removing ALL images (extremely destructive)")
    all_images = docker_client.images.list(all=True)

    deleted = []
    space_reclaimed = 0

    for image in all_images:
        if not image.id:
            continue

        try:
            size = image.attrs.get("Size", 0)
            docker_client.images.remove(image.id, force=True)
            deleted.append({"Deleted": image.id})
            space_reclaimed += size
            logger.debug(f"Force removed image {image.id[:12]}")
        except (APIError, DockerException) as e:
            logger.debug(f"Could not force remove image {image.id[:12]}: {e}")
            continue

    return deleted, space_reclaimed


def force_remove_all_volumes(docker_client: Any) -> list[str]:
    """Remove ALL volumes forcefully, regardless of names or usage.

    This is an extremely destructive operation that removes every single volume,
    including named volumes and those potentially in use.

    Args:
        docker_client: Docker client instance

    Returns:
        List of deleted volume names
    """
    logger.warning("force_all=True: Removing ALL volumes (extremely destructive)")
    all_volumes = docker_client.volumes.list()

    deleted = []
    for volume in all_volumes:
        try:
            volume_name = volume.name
            docker_client.volumes.get(volume_name).remove(force=True)
            deleted.append(volume_name)
            logger.debug(f"Force removed volume {volume_name}")
        except (APIError, DockerException) as e:
            logger.debug(f"Could not force remove volume {volume_name}: {e}")
            continue

    return deleted


def prune_all_unused_images(
    docker_client: Any, filters: dict[str, str | list[str]] | None = None
) -> tuple[list[dict[str, Any]], int]:
    """Remove all unused images (not just dangling ones).

    This removes images that are not in use by any container (including stopped
    containers), but preserves images that are actively in use.

    Args:
        docker_client: Docker client instance
        filters: Optional filters to apply

    Returns:
        Tuple of (deleted_images, space_reclaimed)
    """
    all_images = docker_client.images.list(all=True, filters=filters)

    # Get images in use by containers (including stopped)
    containers = docker_client.containers.list(all=True)
    images_in_use = {container.image.id for container in containers if container.image}

    # Remove images not in use
    deleted = []
    space_reclaimed = 0

    for image in all_images:
        # Skip if image is in use
        if image.id in images_in_use:
            continue

        # Skip if image has no ID (shouldn't happen but be safe)
        if not image.id:
            continue

        try:
            # Get size before removal
            size = image.attrs.get("Size", 0)

            # Remove the image
            docker_client.images.remove(image.id, force=False)

            # Track deletion
            deleted.append({"Deleted": image.id})
            space_reclaimed += size

            logger.debug(f"Removed unused image {image.id[:12]}")
        except (APIError, DockerException) as e:
            # Image might be in use by another image as parent, skip it
            logger.debug(f"Could not remove image {image.id[:12]}: {e}")
            continue

    return deleted, space_reclaimed


# Export all helpers
__all__ = [
    "force_remove_all_images",
    "force_remove_all_volumes",
    "prune_all_unused_images",
]
