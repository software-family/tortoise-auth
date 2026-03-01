"""Async authentication and user management for Tortoise ORM."""

__version__ = "0.1.0"

from tortoise_auth.config import AuthConfig, configure, get_config
from tortoise_auth.events import emit, emitter, on
from tortoise_auth.exceptions import (
    AuthenticationError,
    ConfigurationError,
    EventError,
    InvalidHashError,
    InvalidPasswordError,
    TortoiseAuthError,
)
from tortoise_auth.models import AbstractUser

__all__ = [
    "AbstractUser",
    "AuthConfig",
    "AuthenticationError",
    "ConfigurationError",
    "EventError",
    "InvalidHashError",
    "InvalidPasswordError",
    "TortoiseAuthError",
    "configure",
    "emit",
    "emitter",
    "get_config",
    "on",
]
