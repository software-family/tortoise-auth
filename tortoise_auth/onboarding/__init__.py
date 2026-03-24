"""Onboarding flow engine — protocol, dataclasses, and public API."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of StrEnum for Python 3.10."""


from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from tortoise_auth.config import AuthConfig
    from tortoise_auth.tokens import AuthResult


class OnboardingStepStatus(StrEnum):
    """Status of a single onboarding step."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class StepContext:
    """Context passed to each onboarding step."""

    session_id: str
    step_data: dict[str, Any]
    user_id: str | None
    config: AuthConfig


@dataclass(frozen=True, slots=True)
class StepResult:
    """Result returned by step execution.

    For multi-phase steps, set completed=False to stay on the current step
    while still merging data into step_data (e.g. verification code generation).
    """

    success: bool
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    completed: bool = True


@dataclass(frozen=True, slots=True)
class FieldHint:
    """Describes a single form field for the client."""

    name: str
    field_type: str
    required: bool = True
    label: str = ""
    placeholder: str = ""
    validation: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ClientHint:
    """Describes what the client should render for the current step."""

    step_name: str
    fields: list[FieldHint]
    title: str = ""
    description: str = ""
    skippable: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OnboardingResult:
    """Result returned by OnboardingService methods."""

    session_token: str
    current_step: str
    status: str
    client_hint: ClientHint | None
    step_result: StepResult | None
    auth_result: AuthResult | None
    completed_steps: list[str] = field(default_factory=list)
    remaining_steps: list[str] = field(default_factory=list)


@runtime_checkable
class OnboardingStep(Protocol):
    """Protocol for onboarding steps."""

    @property
    def name(self) -> str: ...

    @property
    def skippable(self) -> bool: ...

    async def is_required(self, context: StepContext) -> bool: ...

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult: ...

    def client_hint(self, context: StepContext) -> ClientHint: ...


__all__ = [
    "ClientHint",
    "FieldHint",
    "OnboardingResult",
    "OnboardingStep",
    "OnboardingStepStatus",
    "StepContext",
    "StepResult",
]
