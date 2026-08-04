"""Toolbox estático en Docker (ver client.py para el diseño completo)."""

from __future__ import annotations

from .client import (
    STATIC_TOOLS,
    DEFAULT_IMAGE,
    DEFAULT_MEMORY_LIMIT,
    ToolboxError,
    ensure_image,
    image_exists,
    image_name,
    is_enabled,
    memory_limit,
    run,
    scratch_dir,
)

__all__ = [
    "STATIC_TOOLS",
    "DEFAULT_IMAGE",
    "DEFAULT_MEMORY_LIMIT",
    "ToolboxError",
    "ensure_image",
    "image_exists",
    "image_name",
    "is_enabled",
    "memory_limit",
    "run",
    "scratch_dir",
]
