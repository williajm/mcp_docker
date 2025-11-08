"""Centralized error message templates for Docker operations.

This module provides consistent error message formatting across the codebase.
All error messages use template strings with format() placeholders.
"""

# Resource not found error messages
ERROR_CONTAINER_NOT_FOUND = "Container not found: {}"
ERROR_IMAGE_NOT_FOUND = "Image not found: {}"
ERROR_NETWORK_NOT_FOUND = "Network not found: {}"
ERROR_VOLUME_NOT_FOUND = "Volume not found: {}"

# Operation error messages
ERROR_FAILED_TO_CREATE_CONTAINER = "Failed to create container: {}"
ERROR_FAILED_TO_START_CONTAINER = "Failed to start container: {}"
ERROR_FAILED_TO_STOP_CONTAINER = "Failed to stop container: {}"
ERROR_FAILED_TO_REMOVE_CONTAINER = "Failed to remove container: {}"
ERROR_FAILED_TO_RESTART_CONTAINER = "Failed to restart container: {}"

ERROR_FAILED_TO_PULL_IMAGE = "Failed to pull image: {}"
ERROR_FAILED_TO_BUILD_IMAGE = "Failed to build image: {}"
ERROR_FAILED_TO_PUSH_IMAGE = "Failed to push image: {}"
ERROR_FAILED_TO_TAG_IMAGE = "Failed to tag image: {}"
ERROR_FAILED_TO_REMOVE_IMAGE = "Failed to remove image: {}"

ERROR_FAILED_TO_CREATE_NETWORK = "Failed to create network: {}"
ERROR_FAILED_TO_CONNECT_NETWORK = "Failed to connect container to network: {}"
ERROR_FAILED_TO_DISCONNECT_NETWORK = "Failed to disconnect container from network: {}"
ERROR_FAILED_TO_REMOVE_NETWORK = "Failed to remove network: {}"

ERROR_FAILED_TO_CREATE_VOLUME = "Failed to create volume: {}"
ERROR_FAILED_TO_REMOVE_VOLUME = "Failed to remove volume: {}"
ERROR_FAILED_TO_INSPECT_VOLUME = "Failed to inspect volume: {}"
