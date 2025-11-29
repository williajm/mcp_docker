"""Centralized error message templates for Docker operations.

This module provides consistent error message formatting across the codebase.
All error messages use template strings with format() placeholders.
"""

# Resource not found error messages (used by tool modules for NotFound exceptions)
ERROR_CONTAINER_NOT_FOUND = "Container not found: {}"
ERROR_IMAGE_NOT_FOUND = "Image not found: {}"
ERROR_NETWORK_NOT_FOUND = "Network not found: {}"
ERROR_VOLUME_NOT_FOUND = "Volume not found: {}"
