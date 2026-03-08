"""Integration tests for the onboarding flow exposed via Starlette endpoints."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
)
from tortoise_auth.models.onboarding import OnboardingSession, hash_session_token
from tortoise_auth.onboarding.service import OnboardingService
from tortoise_auth.onboarding.steps.register import RegisterStep
from tortoise_auth.onboarding.steps.setup_totp import SetupTOTPStep
from tortoise_auth.onboarding.steps.verify_email import VerifyEmailStep

if TYPE_CHECKING:
    from starlette.requests import Request


def _make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-secret-key-that-is-at-least-32-bytes!",
        jwt_secret="test-jwt-secret-key-that-is-at-least-32-bytes!",
        password_validators=[],
        onboarding_session_lifetime=3600,
        onboarding_verification_code_ttl=600,
        onboarding_max_verification_attempts=3,
        **overrides,
    )


def _make_service(config: AuthConfig | None = None) -> OnboardingService:
    cfg = config or _make_config()
    return OnboardingService(
        cfg,
        steps={
            "register": RegisterStep(),
            "verify_email": VerifyEmailStep(),
        },
        pipeline=["register", "verify_email"],
    )


def _serialize_hint(hint):
    if hint is None:
        return None
    return {
        "step_name": hint.step_name,
        "title": hint.title,
        "description": hint.description,
        "skippable": hint.skippable,
        "fields": [
            {
                "name": f.name,
                "type": f.field_type,
                "required": f.required,
                "label": f.label,
                "placeholder": f.placeholder,
            }
            for f in hint.fields
        ],
        "extra": hint.extra,
    }


def _make_app(service: OnboardingService | None = None) -> Starlette:
    svc = service or _make_service()

    async def start(request: Request) -> JSONResponse:
        body = await request.json()
        ip = request.client.host if request.client else ""
        result = await svc.start(body["email"], ip_address=ip)
        return JSONResponse(
            {
                "session_token": result.session_token,
                "current_step": result.current_step,
                "status": result.status,
                "client_hint": _serialize_hint(result.client_hint),
                "completed_steps": result.completed_steps,
                "remaining_steps": result.remaining_steps,
            }
        )

    async def advance(request: Request) -> JSONResponse:
        body = await request.json()
        token = body.pop("session_token")
        skip = body.pop("skip", False)

        try:
            result = await svc.advance(token, body, skip=skip)
        except OnboardingSessionExpiredError:
            return JSONResponse({"error": "Session expired"}, status_code=410)
        except OnboardingSessionInvalidError as exc:
            return JSONResponse({"error": exc.reason}, status_code=404)
        except OnboardingFlowCompleteError:
            return JSONResponse({"error": "Already completed"}, status_code=409)

        resp: dict = {
            "status": result.status,
            "current_step": result.current_step,
            "client_hint": _serialize_hint(result.client_hint),
            "completed_steps": result.completed_steps,
            "remaining_steps": result.remaining_steps,
        }
        if result.step_result:
            resp["errors"] = result.step_result.errors
        if result.auth_result:
            resp["access_token"] = result.auth_result.access_token
            resp["refresh_token"] = result.auth_result.refresh_token

        return JSONResponse(resp)

    async def resume(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            result = await svc.resume(body["session_token"])
        except OnboardingSessionExpiredError:
            return JSONResponse({"error": "Session expired"}, status_code=410)
        except OnboardingSessionInvalidError as exc:
            return JSONResponse({"error": exc.reason}, status_code=404)
        except OnboardingFlowCompleteError:
            return JSONResponse({"error": "Already completed"}, status_code=409)

        return JSONResponse(
            {
                "status": result.status,
                "current_step": result.current_step,
                "client_hint": _serialize_hint(result.client_hint),
                "completed_steps": result.completed_steps,
                "remaining_steps": result.remaining_steps,
            }
        )

    return Starlette(
        routes=[
            Route("/onboarding/start", start, methods=["POST"]),
            Route("/onboarding/advance", advance, methods=["POST"]),
            Route("/onboarding/resume", resume, methods=["POST"]),
        ]
    )


def _client(app: Starlette) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


@pytest.fixture(autouse=True)
def _clear_events():
    emitter.clear()
    yield
    emitter.clear()


class TestStartEndpoint:
    async def test_start_returns_register_step(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/start",
                json={"email": "user@example.com"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "in_progress"
        assert data["current_step"] == "register"
        assert data["session_token"] != ""
        assert data["client_hint"]["step_name"] == "register"
        assert "register" in data["remaining_steps"]

    async def test_start_register_fields(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/start",
                json={"email": "fields@example.com"},
            )
        fields = resp.json()["client_hint"]["fields"]
        names = [f["name"] for f in fields]
        assert "email" in names
        assert "password" in names
        assert "password_confirm" in names


class TestAdvanceEndpoint:
    async def test_register_success_moves_to_verify(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "adv@example.com"},
            )
            token = start.json()["session_token"]

            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "adv@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

        data = resp.json()
        assert resp.status_code == 200
        assert data["status"] == "in_progress"
        assert data["current_step"] == "verify_email"
        assert "register" in data["completed_steps"]

    async def test_register_validation_error(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "err@example.com"},
            )
            token = start.json()["session_token"]

            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "",
                    "password": "",
                    "password_confirm": "",
                },
            )

        data = resp.json()
        assert resp.status_code == 200
        assert data["status"] == "error"
        assert len(data["errors"]) > 0
        assert data["client_hint"]["step_name"] == "register"

    async def test_password_mismatch(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "mis@example.com"},
            )
            token = start.json()["session_token"]

            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "mis@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "DifferentP@ss1",
                },
            )

        data = resp.json()
        assert data["status"] == "error"
        assert any("match" in e.lower() for e in data["errors"])


class TestFullFlow:
    async def test_register_send_code_verify_code(self) -> None:
        """Full end-to-end: register → send code → verify code → tokens."""
        codes: list[str] = []

        @emitter.on("verification_code_generated")
        async def capture(*, email: str, code: str) -> None:
            codes.append(code)

        app = _make_app()
        async with _client(app) as c:
            # 1. Start
            r_start = await c.post(
                "/onboarding/start",
                json={"email": "full@example.com"},
            )
            token = r_start.json()["session_token"]

            # 2. Register
            r_reg = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "full@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )
            assert r_reg.json()["current_step"] == "verify_email"

            # 3. Send verification code (empty data)
            r_send = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )
            assert r_send.json()["status"] == "in_progress"
            assert r_send.json()["current_step"] == "verify_email"
            assert len(codes) == 1

            # 4. Verify the code
            r_verify = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "code": codes[0],
                },
            )

        data = r_verify.json()
        assert data["status"] == "completed"
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] != ""
        assert data["refresh_token"] != ""

    async def test_wrong_code_then_correct_code(self) -> None:
        """Wrong code returns error, correct code completes."""
        codes: list[str] = []

        @emitter.on("verification_code_generated")
        async def capture(*, email: str, code: str) -> None:
            codes.append(code)

        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "retry@example.com"},
            )
            token = start.json()["session_token"]

            # Register
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "retry@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

            # Send code
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )

            # Wrong code
            r_wrong = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "code": "000000",
                },
            )
            assert r_wrong.json()["status"] == "error"
            assert any("Invalid" in e for e in r_wrong.json()["errors"])

            # Correct code
            r_ok = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "code": codes[0],
                },
            )

        assert r_ok.json()["status"] == "completed"
        assert "access_token" in r_ok.json()


class TestResumeEndpoint:
    async def test_resume_at_register(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "resume@example.com"},
            )
            token = start.json()["session_token"]

            resp = await c.post(
                "/onboarding/resume",
                json={
                    "session_token": token,
                },
            )

        data = resp.json()
        assert resp.status_code == 200
        assert data["status"] == "in_progress"
        assert data["current_step"] == "register"

    async def test_resume_at_verify_email(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "resume2@example.com"},
            )
            token = start.json()["session_token"]

            # Advance past register
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "resume2@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

            # Resume should be at verify_email
            resp = await c.post(
                "/onboarding/resume",
                json={
                    "session_token": token,
                },
            )

        assert resp.json()["current_step"] == "verify_email"


class TestErrorResponses:
    async def test_invalid_token_returns_404(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": "nonexistent-token",
                    "email": "x@x.com",
                },
            )
        assert resp.status_code == 404
        assert resp.json()["error"] == "Session not found"

    async def test_expired_session_returns_410(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "expired@example.com"},
            )
            token = start.json()["session_token"]

        # Expire the session manually
        token_hash = hash_session_token(token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.expires_at = tz_now() - timedelta(seconds=1)
        await session.save(update_fields=["expires_at"])

        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "expired@example.com",
                },
            )
        assert resp.status_code == 410

    async def test_completed_flow_returns_409(self) -> None:
        codes: list[str] = []

        @emitter.on("verification_code_generated")
        async def capture(*, email: str, code: str) -> None:
            codes.append(code)

        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "done@example.com"},
            )
            token = start.json()["session_token"]

            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "done@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "code": codes[0],
                },
            )

            # Try to advance again
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )
        assert resp.status_code == 409

    async def test_invalidated_session_returns_404(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "inv@example.com"},
            )
            token = start.json()["session_token"]

        # Invalidate the session
        token_hash = hash_session_token(token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.is_invalidated = True
        await session.save(update_fields=["is_invalidated"])

        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )
        assert resp.status_code == 404

    async def test_resume_expired_returns_410(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "rexp@example.com"},
            )
            token = start.json()["session_token"]

        token_hash = hash_session_token(token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.expires_at = tz_now() - timedelta(seconds=1)
        await session.save(update_fields=["expires_at"])

        async with _client(app) as c:
            resp = await c.post(
                "/onboarding/resume",
                json={
                    "session_token": token,
                },
            )
        assert resp.status_code == 410


class TestSkipEndpoint:
    async def test_skip_non_skippable_returns_error(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "skip@example.com"},
            )
            token = start.json()["session_token"]

            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "skip": True,
                },
            )

        data = resp.json()
        assert data["status"] == "error"
        assert any("cannot be skipped" in e for e in data["errors"])

    async def test_skip_skippable_step(self) -> None:
        config = _make_config(onboarding_require_totp=True)
        svc = OnboardingService(
            config,
            steps={
                "register": RegisterStep(),
                "setup_totp": SetupTOTPStep(),
            },
            pipeline=["register", "setup_totp"],
        )
        app = _make_app(service=svc)

        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "skiptotp@example.com"},
            )
            token = start.json()["session_token"]

            # Register
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "skiptotp@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

            # Skip TOTP → should complete
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "skip": True,
                },
            )

        data = resp.json()
        assert data["status"] == "completed"
        assert "access_token" in data


class TestSessionInvalidation:
    async def test_new_start_invalidates_old_session(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            r1 = await c.post(
                "/onboarding/start",
                json={"email": "same@example.com"},
            )
            token1 = r1.json()["session_token"]

            r2 = await c.post(
                "/onboarding/start",
                json={"email": "same@example.com"},
            )
            token2 = r2.json()["session_token"]

            # Old token should be invalidated
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token1,
                    "email": "same@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )
            assert resp.status_code == 404

            # New token should work
            resp2 = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token2,
                    "email": "same@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )
            assert resp2.json()["status"] == "in_progress"


class TestDuplicateEmail:
    async def test_register_duplicate_email_returns_error(self) -> None:
        app = _make_app()
        async with _client(app) as c:
            # First user registers
            s1 = await c.post(
                "/onboarding/start",
                json={"email": "dup@example.com"},
            )
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": s1.json()["session_token"],
                    "email": "dup@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

            # Second user tries same email
            s2 = await c.post(
                "/onboarding/start",
                json={"email": "dup2@example.com"},
            )
            resp = await c.post(
                "/onboarding/advance",
                json={
                    "session_token": s2.json()["session_token"],
                    "email": "dup@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )

        data = resp.json()
        assert data["status"] == "error"
        assert any("taken" in e.lower() for e in data["errors"])


class TestEvents:
    async def test_full_flow_emits_lifecycle_events(self) -> None:
        events: list[str] = []
        codes: list[str] = []

        @emitter.on("onboarding_started")
        async def on_start(**kw):
            events.append("started")

        @emitter.on("onboarding_step_completed")
        async def on_step(**kw):
            events.append(f"step_completed:{kw['step_name']}")

        @emitter.on("onboarding_completed")
        async def on_done(**kw):
            events.append("completed")

        @emitter.on("verification_code_generated")
        async def on_code(*, email: str, code: str):
            codes.append(code)
            events.append("code_generated")

        app = _make_app()
        async with _client(app) as c:
            start = await c.post(
                "/onboarding/start",
                json={"email": "evt@example.com"},
            )
            token = start.json()["session_token"]

            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "email": "evt@example.com",
                    "password": "StrongP@ss1",
                    "password_confirm": "StrongP@ss1",
                },
            )
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                },
            )
            await c.post(
                "/onboarding/advance",
                json={
                    "session_token": token,
                    "code": codes[0],
                },
            )

        assert events == [
            "started",
            "step_completed:register",
            "code_generated",
            "step_completed:verify_email",
            "completed",
        ]
