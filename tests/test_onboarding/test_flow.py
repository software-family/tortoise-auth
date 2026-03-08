"""Tests for OnboardingFlow state machine logic."""

from __future__ import annotations

from typing import Any

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.onboarding import (
    ClientHint,
    OnboardingStepStatus,
    StepContext,
    StepResult,
)
from tortoise_auth.onboarding.flow import OnboardingFlow


class AlwaysRequiredStep:
    """Test step that is always required."""

    def __init__(self, step_name: str = "step_a", *, step_skippable: bool = False) -> None:
        self._name = step_name
        self._skippable = step_skippable

    @property
    def name(self) -> str:
        return self._name

    @property
    def skippable(self) -> bool:
        return self._skippable

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        return StepResult(success=True, data={"done": True})

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(step_name=self._name, fields=[])


class NeverRequiredStep:
    """Test step that is never required (always skipped)."""

    @property
    def name(self) -> str:
        return "optional"

    @property
    def skippable(self) -> bool:
        return True

    async def is_required(self, context: StepContext) -> bool:
        return False

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        return StepResult(success=True)

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(step_name="optional", fields=[])


class FailingStep:
    """Test step that always fails."""

    @property
    def name(self) -> str:
        return "failing"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        return StepResult(success=False, errors=["always fails"])

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(step_name="failing", fields=[])


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(user_model="models.MinimalUser")


@pytest.fixture()
def context(config: AuthConfig) -> StepContext:
    return StepContext(session_id="test-session", step_data={}, user_id=None, config=config)


class TestGetNextStep:
    async def test_returns_first_required_step(self, context: StepContext) -> None:
        step_a = AlwaysRequiredStep("step_a")
        step_b = AlwaysRequiredStep("step_b")
        flow = OnboardingFlow({"step_a": step_a, "step_b": step_b})

        result = await flow.get_next_step(["step_a", "step_b"], 0, {}, context)
        assert result is not None
        index, step = result
        assert index == 0
        assert step.name == "step_a"

    async def test_skips_completed_steps(self, context: StepContext) -> None:
        step_a = AlwaysRequiredStep("step_a")
        step_b = AlwaysRequiredStep("step_b")
        flow = OnboardingFlow({"step_a": step_a, "step_b": step_b})

        state = {"step_a": OnboardingStepStatus.COMPLETED}
        result = await flow.get_next_step(["step_a", "step_b"], 0, state, context)
        assert result is not None
        index, step = result
        assert index == 1
        assert step.name == "step_b"

    async def test_skips_not_required_steps(self, context: StepContext) -> None:
        optional = NeverRequiredStep()
        required = AlwaysRequiredStep("step_b")
        flow = OnboardingFlow({"optional": optional, "step_b": required})

        state: dict[str, str] = {}
        result = await flow.get_next_step(["optional", "step_b"], 0, state, context)
        assert result is not None
        index, step = result
        assert index == 1
        assert step.name == "step_b"
        # Optional should have been marked as skipped
        assert state["optional"] == OnboardingStepStatus.SKIPPED

    async def test_returns_none_when_all_complete(self, context: StepContext) -> None:
        step_a = AlwaysRequiredStep("step_a")
        flow = OnboardingFlow({"step_a": step_a})

        state = {"step_a": OnboardingStepStatus.COMPLETED}
        result = await flow.get_next_step(["step_a"], 0, state, context)
        assert result is None

    async def test_skips_unknown_steps(self, context: StepContext) -> None:
        step_b = AlwaysRequiredStep("step_b")
        flow = OnboardingFlow({"step_b": step_b})

        result = await flow.get_next_step(["unknown", "step_b"], 0, {}, context)
        assert result is not None
        _, step = result
        assert step.name == "step_b"


class TestExecuteStep:
    async def test_delegates_to_step(self, context: StepContext) -> None:
        step = AlwaysRequiredStep("step_a")
        flow = OnboardingFlow({"step_a": step})

        result = await flow.execute_step(step, context, {})
        assert result.success is True
        assert result.data == {"done": True}

    async def test_failing_step(self, context: StepContext) -> None:
        step = FailingStep()
        flow = OnboardingFlow({"failing": step})

        result = await flow.execute_step(step, context, {})
        assert result.success is False
        assert "always fails" in result.errors


class TestHandleSkip:
    def test_skippable_step(self) -> None:
        step = AlwaysRequiredStep("step_a", step_skippable=True)
        flow = OnboardingFlow({"step_a": step})

        result = flow.handle_skip(step)
        assert result.success is True

    def test_non_skippable_step(self) -> None:
        step = AlwaysRequiredStep("step_a", step_skippable=False)
        flow = OnboardingFlow({"step_a": step})

        result = flow.handle_skip(step)
        assert result.success is False
        assert "cannot be skipped" in result.errors[0]


class TestIsComplete:
    def test_all_completed(self) -> None:
        flow = OnboardingFlow({})
        state = {
            "a": OnboardingStepStatus.COMPLETED,
            "b": OnboardingStepStatus.SKIPPED,
        }
        assert flow.is_complete(["a", "b"], state) is True

    def test_not_all_completed(self) -> None:
        flow = OnboardingFlow({})
        state = {"a": OnboardingStepStatus.COMPLETED}
        assert flow.is_complete(["a", "b"], state) is False

    def test_empty_pipeline(self) -> None:
        flow = OnboardingFlow({})
        assert flow.is_complete([], {}) is True


class TestHelpers:
    def test_completed_steps(self) -> None:
        flow = OnboardingFlow({})
        state = {
            "a": OnboardingStepStatus.COMPLETED,
            "b": OnboardingStepStatus.PENDING,
            "c": OnboardingStepStatus.SKIPPED,
        }
        assert flow.completed_steps(["a", "b", "c"], state) == ["a", "c"]

    def test_remaining_steps(self) -> None:
        flow = OnboardingFlow({})
        state = {
            "a": OnboardingStepStatus.COMPLETED,
            "b": OnboardingStepStatus.PENDING,
        }
        assert flow.remaining_steps(["a", "b", "c"], state) == ["b", "c"]

    def test_get_step(self) -> None:
        step = AlwaysRequiredStep("step_a")
        flow = OnboardingFlow({"step_a": step})
        assert flow.get_step("step_a") is step
        assert flow.get_step("nonexistent") is None
