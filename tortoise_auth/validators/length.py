"""Minimum length password validator."""

from __future__ import annotations

from typing import Any


class MinimumLengthValidator:
    """Validates that a password meets a minimum length requirement."""

    def __init__(self, min_length: int = 8) -> None:
        self.min_length = min_length

    def validate(self, password: str, user: Any = None) -> None:
        if len(password) < self.min_length:
            raise ValueError(
                f"This password is too short. It must contain at least {self.min_length} characters."
            )

    def get_help_text(self) -> str:
        return f"Your password must contain at least {self.min_length} characters."
