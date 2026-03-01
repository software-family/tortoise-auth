"""Password validation for tortoise-auth."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from tortoise_auth.exceptions import InvalidPasswordError

if TYPE_CHECKING:
    from tortoise.models import Model


@runtime_checkable
class PasswordValidator(Protocol):
    """Protocol for password validators."""

    def validate(self, password: str, user: Any = None) -> None:
        """Validate a password. Raise ValueError with a message on failure."""
        ...

    def get_help_text(self) -> str:
        """Return a human-readable description of the validation rule."""
        ...


def validate_password(
    password: str,
    user: Model | None = None,
    validators: list[PasswordValidator] | None = None,
) -> None:
    """Run all validators and collect errors before raising.

    If ``validators`` is None, the defaults from the global config are used.
    """
    if validators is None:
        from tortoise_auth.config import get_config

        validators = get_config().password_validators

    errors: list[str] = []
    for validator in validators:
        try:
            validator.validate(password, user)
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise InvalidPasswordError(errors)


__all__ = [
    "PasswordValidator",
    "validate_password",
]
