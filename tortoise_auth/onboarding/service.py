"""OnboardingService — orchestrates the onboarding flow with session management."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import (
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
)
from tortoise_auth.models.onboarding import (
    OnboardingSession,
    generate_session_token,
    hash_session_token,
)
from tortoise_auth.onboarding import (
    OnboardingResult,
    OnboardingStep,
    OnboardingStepStatus,
    StepContext,
)
from tortoise_auth.onboarding.flow import OnboardingFlow
from tortoise_auth.tokens import AuthResult

if TYPE_CHECKING:
    from tortoise_auth.rate_limit import RateLimitBackend


class OnboardingService:
    """High-level service for managing onboarding flows."""

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        steps: dict[str, OnboardingStep] | None = None,
        pipeline: list[str] | None = None,
        rate_limiter: RateLimitBackend | None = None,
    ) -> None:
        self._config = config
        self._pipeline = pipeline
        self._rate_limiter = rate_limiter
        self._flow = OnboardingFlow(steps or {})
        self._steps = steps or {}

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    @property
    def pipeline(self) -> list[str]:
        return self._pipeline or list(self._steps.keys())

    async def start(self, email: str, *, ip_address: str = "") -> OnboardingResult:
        """Start a new onboarding flow for the given email."""
        if self._rate_limiter is not None:
            result = await self._rate_limiter.check(email)
            if not result.allowed:
                from tortoise_auth.exceptions import RateLimitError

                raise RateLimitError(email, result.retry_after)

        # Invalidate previous sessions for this email
        if self.config.onboarding_invalidate_previous_sessions:
            await OnboardingSession.filter(
                email=email,
                is_invalidated=False,
                completed_at=None,
            ).update(is_invalidated=True)

        # Generate session token
        raw_token = generate_session_token(self.config.onboarding_session_token_length)
        token_hash = hash_session_token(raw_token)

        pipeline = self.pipeline
        now = tz_now()
        expires_at = now + timedelta(seconds=self.config.onboarding_session_lifetime)

        session = await OnboardingSession.create(
            token_hash=token_hash,
            email=email,
            pipeline=json.dumps(pipeline),
            step_state=json.dumps({}),
            step_data=json.dumps({}),
            ip_address=ip_address,
            expires_at=expires_at,
        )

        context = StepContext(
            session_id=str(session.id),
            step_data={},
            user_id=None,
            config=self.config,
        )

        step_state: dict[str, str] = {}
        next_result = await self._flow.get_next_step(pipeline, 0, step_state, context)

        # Persist any skipped steps from get_next_step
        if step_state:
            session.step_state = json.dumps(step_state)
            await session.save(update_fields=["step_state"])

        await emit(
            "onboarding_started",
            email=email,
            session_id=str(session.id),
            pipeline=pipeline,
        )

        if next_result is None:
            return await self._finalize(session, raw_token)

        index, step = next_result
        session.current_step_index = index
        await session.save(update_fields=["current_step_index"])

        hint = step.client_hint(context)
        return OnboardingResult(
            session_token=raw_token,
            current_step=step.name,
            status="in_progress",
            client_hint=hint,
            step_result=None,
            auth_result=None,
            completed_steps=self._flow.completed_steps(pipeline, step_state),
            remaining_steps=self._flow.remaining_steps(pipeline, step_state),
        )

    async def advance(
        self,
        session_token: str,
        data: dict[str, Any],
        *,
        skip: bool = False,
    ) -> OnboardingResult:
        """Advance the onboarding flow by executing or skipping the current step."""
        session = await self._lookup_session(session_token)
        pipeline = json.loads(session.pipeline)
        step_state: dict[str, str] = json.loads(session.step_state)
        step_data: dict[str, Any] = json.loads(session.step_data)

        if self._flow.is_complete(pipeline, step_state):
            raise OnboardingFlowCompleteError()

        current_step_name = pipeline[session.current_step_index]
        step = self._flow.get_step(current_step_name)
        if step is None:
            raise OnboardingSessionInvalidError(f"Step {current_step_name!r} not found")

        user_id = session.user_id or step_data.get("user_id") or None
        context = StepContext(
            session_id=str(session.id),
            step_data=step_data,
            user_id=user_id,
            config=self.config,
        )

        if skip:
            result = self._flow.handle_skip(step)
            if result.success:
                step_state[current_step_name] = OnboardingStepStatus.SKIPPED
                await emit(
                    "onboarding_step_skipped",
                    session_id=str(session.id),
                    step_name=current_step_name,
                )
            else:
                await emit(
                    "onboarding_step_failed",
                    session_id=str(session.id),
                    step_name=current_step_name,
                    errors=result.errors,
                )
                hint = step.client_hint(context)
                return OnboardingResult(
                    session_token=session_token,
                    current_step=current_step_name,
                    status="error",
                    client_hint=hint,
                    step_result=result,
                    auth_result=None,
                    completed_steps=self._flow.completed_steps(pipeline, step_state),
                    remaining_steps=self._flow.remaining_steps(pipeline, step_state),
                )
        else:
            result = await self._flow.execute_step(step, context, data)

            if result.success and result.completed:
                step_state[current_step_name] = OnboardingStepStatus.COMPLETED
                step_data.update(result.data)

                # Track user_id if returned by step
                if "user_id" in result.data:
                    session.user_id = result.data["user_id"]

                await emit(
                    "onboarding_step_completed",
                    session_id=str(session.id),
                    step_name=current_step_name,
                    user_id=session.user_id,
                )
            elif result.success and not result.completed:
                # Multi-phase step: merge data but stay on current step
                step_data.update(result.data)
                session.step_data = json.dumps(step_data)
                await session.save(update_fields=["step_data"])

                updated_context = StepContext(
                    session_id=str(session.id),
                    step_data=step_data,
                    user_id=session.user_id or step_data.get("user_id") or None,
                    config=self.config,
                )
                hint = step.client_hint(updated_context)
                return OnboardingResult(
                    session_token=session_token,
                    current_step=current_step_name,
                    status="in_progress",
                    client_hint=hint,
                    step_result=result,
                    auth_result=None,
                    completed_steps=self._flow.completed_steps(pipeline, step_state),
                    remaining_steps=self._flow.remaining_steps(pipeline, step_state),
                )
            else:
                # On failure, still merge data (e.g. attempt counters)
                step_data.update(result.data)
                session.step_data = json.dumps(step_data)
                await session.save(update_fields=["step_data"])

                # Check if max attempts exceeded → invalidate session
                if result.data.get("_max_attempts_exceeded"):
                    session.is_invalidated = True
                    await session.save(update_fields=["is_invalidated"])

                await emit(
                    "onboarding_step_failed",
                    session_id=str(session.id),
                    step_name=current_step_name,
                    errors=result.errors,
                )

                # Rebuild context with updated step_data for client_hint
                updated_context = StepContext(
                    session_id=str(session.id),
                    step_data=step_data,
                    user_id=session.user_id or step_data.get("user_id") or None,
                    config=self.config,
                )
                hint = step.client_hint(updated_context)
                return OnboardingResult(
                    session_token=session_token,
                    current_step=current_step_name,
                    status="error",
                    client_hint=hint,
                    step_result=result,
                    auth_result=None,
                    completed_steps=self._flow.completed_steps(pipeline, step_state),
                    remaining_steps=self._flow.remaining_steps(pipeline, step_state),
                )

        # Step succeeded (or was skipped) — persist and find next step
        session.step_state = json.dumps(step_state)
        session.step_data = json.dumps(step_data)
        await session.save(update_fields=["step_state", "step_data", "user_id"])

        # Build context with updated data for next step resolution
        updated_user_id = session.user_id or step_data.get("user_id") or None
        updated_context = StepContext(
            session_id=str(session.id),
            step_data=step_data,
            user_id=updated_user_id,
            config=self.config,
        )

        next_result = await self._flow.get_next_step(
            pipeline, session.current_step_index + 1, step_state, updated_context
        )

        # Persist any newly skipped steps
        session.step_state = json.dumps(step_state)
        await session.save(update_fields=["step_state"])

        if next_result is None:
            return await self._finalize(session, session_token)

        index, next_step = next_result
        session.current_step_index = index
        await session.save(update_fields=["current_step_index"])

        hint = next_step.client_hint(updated_context)
        return OnboardingResult(
            session_token=session_token,
            current_step=next_step.name,
            status="in_progress",
            client_hint=hint,
            step_result=result,
            auth_result=None,
            completed_steps=self._flow.completed_steps(pipeline, step_state),
            remaining_steps=self._flow.remaining_steps(pipeline, step_state),
        )

    async def resume(self, session_token: str) -> OnboardingResult:
        """Resume an existing onboarding flow without executing anything."""
        session = await self._lookup_session(session_token)
        pipeline = json.loads(session.pipeline)
        step_state: dict[str, str] = json.loads(session.step_state)
        step_data: dict[str, Any] = json.loads(session.step_data)

        if self._flow.is_complete(pipeline, step_state):
            raise OnboardingFlowCompleteError()

        current_step_name = pipeline[session.current_step_index]
        step = self._flow.get_step(current_step_name)
        if step is None:
            raise OnboardingSessionInvalidError(f"Step {current_step_name!r} not found")

        user_id = session.user_id or step_data.get("user_id") or None
        context = StepContext(
            session_id=str(session.id),
            step_data=step_data,
            user_id=user_id,
            config=self.config,
        )

        hint = step.client_hint(context)
        return OnboardingResult(
            session_token=session_token,
            current_step=current_step_name,
            status="in_progress",
            client_hint=hint,
            step_result=None,
            auth_result=None,
            completed_steps=self._flow.completed_steps(pipeline, step_state),
            remaining_steps=self._flow.remaining_steps(pipeline, step_state),
        )

    async def cleanup_expired(self) -> int:
        """Delete expired onboarding sessions. Returns number deleted."""
        now = tz_now()
        deleted = await OnboardingSession.filter(expires_at__lt=now).delete()
        return deleted

    async def _finalize(self, session: OnboardingSession, session_token: str) -> OnboardingResult:
        """Complete the onboarding flow and issue auth tokens."""
        session.completed_at = tz_now()
        await session.save(update_fields=["completed_at"])

        step_data: dict[str, Any] = json.loads(session.step_data)
        user_id = session.user_id or step_data.get("user_id", "")
        pipeline = json.loads(session.pipeline)
        step_state: dict[str, str] = json.loads(session.step_state)

        auth_result: AuthResult | None = None
        if user_id:
            from tortoise_auth.services.auth import AuthService

            auth_service = AuthService(self.config)
            tokens = await auth_service.backend.create_tokens(user_id)

            # Resolve user for AuthResult
            user_model = auth_service._resolve_user_model()
            user = await user_model.filter(pk=user_id).first()

            auth_result = AuthResult(
                user=user,
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
            )

            await emit("onboarding_completed", user=user, session_id=str(session.id))

        return OnboardingResult(
            session_token=session_token,
            current_step="",
            status="completed",
            client_hint=None,
            step_result=None,
            auth_result=auth_result,
            completed_steps=self._flow.completed_steps(pipeline, step_state),
            remaining_steps=[],
        )

    async def _lookup_session(self, session_token: str) -> OnboardingSession:
        """Look up and validate a session by raw token."""
        token_hash = hash_session_token(session_token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()

        if session is None:
            raise OnboardingSessionInvalidError()

        if session.is_invalidated:
            raise OnboardingSessionInvalidError("Session has been invalidated")

        if session.completed_at is not None:
            raise OnboardingFlowCompleteError()

        if session.is_expired:
            await emit(
                "onboarding_session_expired",
                session_id=str(session.id),
                email=session.email,
            )
            raise OnboardingSessionExpiredError(str(session.id))

        return session
