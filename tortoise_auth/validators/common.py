"""Common password validator."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class CommonPasswordValidator:
    """Validates that a password is not in a list of common passwords."""

    def __init__(self, password_list_path: str | Path | None = None) -> None:
        if password_list_path is None:
            password_list_path = Path(__file__).parent / "common_passwords.txt"
        self._path = Path(password_list_path)
        self._passwords: frozenset[str] | None = None

    @property
    def passwords(self) -> frozenset[str]:
        if self._passwords is None:
            with open(self._path) as f:
                self._passwords = frozenset(line.strip().lower() for line in f if line.strip())
        return self._passwords

    def validate(self, password: str, user: Any = None) -> None:
        if password.lower() in self.passwords:
            raise ValueError("This password is too common.")

    def get_help_text(self) -> str:
        return "Your password can't be a commonly used password."
