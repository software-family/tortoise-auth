"""OnboardingFlow — pure state machine engine for step orchestration."""

from __future__ import annotations

from typing import Any

from tortoise_auth.onboarding import (
    OnboardingStep,
    OnboardingStepStatus,
    StepContext,
    StepResult,
)


class OnboardingFlow:
    """Drives the onboarding pipeline through its steps.

    Pure logic — no I/O of its own. Delegates execution to step instances.
    """

    def __init__(self, steps: dict[str, OnboardingStep]) -> None:
        self._steps = steps

    async def get_next_step(
        self,
        pipeline: list[str],
        current_index: int,
        step_state: dict[str, str],
        context: StepContext,
    ) -> tuple[int, OnboardingStep] | None:
        """Find the next required step starting from current_index.

        Skips steps that are already completed/skipped or not required.
        Returns (index, step) or None if all steps are done.
        """
        for i in range(current_index, len(pipeline)):
            step_name = pipeline[i]
            status = step_state.get(step_name)
            if status in (OnboardingStepStatus.COMPLETED, OnboardingStepStatus.SKIPPED):
                continue
            step = self._steps.get(step_name)
            if step is None:
                continue
            if not await step.is_required(context):
                step_state[step_name] = OnboardingStepStatus.SKIPPED
                continue
            return i, step
        return None

    async def execute_step(
        self,
        step: OnboardingStep,
        context: StepContext,
        data: dict[str, Any],
    ) -> StepResult:
        """Execute a step with the given data."""
        return await step.execute(context, data)

    def handle_skip(
        self,
        step: OnboardingStep,
    ) -> StepResult:
        """Attempt to skip a step. Returns error if not skippable."""
        if not step.skippable:
            return StepResult(
                success=False,
                errors=[f"Step {step.name!r} cannot be skipped"],
            )
        return StepResult(success=True)

    def is_complete(
        self,
        pipeline: list[str],
        step_state: dict[str, str],
    ) -> bool:
        """Check if all pipeline steps are completed or skipped."""
        for step_name in pipeline:
            status = step_state.get(step_name)
            if status not in (OnboardingStepStatus.COMPLETED, OnboardingStepStatus.SKIPPED):
                return False
        return True

    def get_step(self, name: str) -> OnboardingStep | None:
        """Look up a step by name."""
        return self._steps.get(name)

    def completed_steps(self, pipeline: list[str], step_state: dict[str, str]) -> list[str]:
        """Return names of completed or skipped steps."""
        return [
            name
            for name in pipeline
            if step_state.get(name)
            in (OnboardingStepStatus.COMPLETED, OnboardingStepStatus.SKIPPED)
        ]

    def remaining_steps(self, pipeline: list[str], step_state: dict[str, str]) -> list[str]:
        """Return names of steps not yet completed or skipped."""
        return [
            name
            for name in pipeline
            if step_state.get(name)
            not in (OnboardingStepStatus.COMPLETED, OnboardingStepStatus.SKIPPED)
        ]
