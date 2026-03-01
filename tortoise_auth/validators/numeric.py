"""Numeric password validator."""

from __future__ import annotations

from typing import Any


class NumericPasswordValidator:
    """Validates that a password is not entirely numeric."""

    def validate(self, password: str, user: Any = None) -> None:
        if password.isdigit():
            raise ValueError("This password is entirely numeric.")

    def get_help_text(self) -> str:
        return "Your password can't be entirely numeric."
