"""User attribute similarity password validator."""

from __future__ import annotations

import difflib
from typing import Any


class UserAttributeSimilarityValidator:
    """Validates that a password is not too similar to user attributes."""

    def __init__(
        self,
        user_attributes: tuple[str, ...] = ("email",),
        max_similarity: float = 0.7,
    ) -> None:
        self.user_attributes = user_attributes
        self.max_similarity = max_similarity

    def validate(self, password: str, user: Any = None) -> None:
        if user is None:
            return

        password_lower = password.lower()
        for attr_name in self.user_attributes:
            value = getattr(user, attr_name, None)
            if not value or not isinstance(value, str):
                continue

            values_to_check = [value]
            if "@" in value:
                values_to_check.append(value.split("@")[0])

            for val in values_to_check:
                val_lower = val.lower()
                if not val_lower:
                    continue
                ratio = difflib.SequenceMatcher(None, password_lower, val_lower).quick_ratio()
                if ratio >= self.max_similarity:
                    raise ValueError(
                        f"The password is too similar to the {attr_name}."
                    )

    def get_help_text(self) -> str:
        return "Your password can't be too similar to your other personal information."
