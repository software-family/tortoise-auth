"""Tests for the passwordless passkey_admin Starlette example.

Covers:
- The custom ``PasswordlessRegisterStep`` (user creation with unusable password).
- The ``MandatoryRegisterPasskeyStep`` metadata.
- The full onboarding pipeline end-to-end (invitation → user creation),
  without driving the WebAuthn-specific third step (which needs py_webauthn
  mocked and is covered by the dedicated passkey tests).
- A regression test for the TortoiseContext fallback: request handlers must
  be able to query the DB even though ``Tortoise.init()`` ran in the lifespan
  task.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from examples.starlette_example import passkey_admin as example
from tortoise_auth import config as config_module
from tortoise_auth.onboarding import StepContext


@pytest.fixture(autouse=True)
def _restore_example_config():
    """Make sure the example's module-level ``configure(...)`` is re-applied
    after any test that swaps the global config via ``_clear_config`` patterns.
    """
    config_module.configure(example.config)
    yield
    config_module.configure(example.config)


def _make_context(step_data: dict) -> StepContext:
    return StepContext(
        session_id="test-session",
        step_data=step_data,
        user_id=None,
        config=example.config,
    )


class TestPasswordlessRegisterStep:
    async def test_creates_user_with_unusable_password(self):
        step = example.PasswordlessRegisterStep()
        context = _make_context({"email": "alice@example.com"})

        result = await step.execute(context, {})

        assert result.success is True
        assert "user_id" in result.data

        user = await example.User.filter(email="alice@example.com").first()
        assert user is not None
        assert user.is_active is True
        assert user.is_verified is True
        assert user.has_usable_password() is False

    async def test_fails_without_email_in_step_data(self):
        step = example.PasswordlessRegisterStep()
        context = _make_context({})

        result = await step.execute(context, {})

        assert result.success is False
        assert any("invitation" in err.lower() for err in result.errors)

    async def test_is_idempotent_when_user_exists(self):
        existing = example.User(email="bob@example.com", is_active=True)
        existing.set_unusable_password()
        await existing.save()

        step = example.PasswordlessRegisterStep()
        context = _make_context({"email": "bob@example.com"})

        result = await step.execute(context, {})

        assert result.success is True
        assert result.data["user_id"] == str(existing.pk)
        assert await example.User.filter(email="bob@example.com").count() == 1

    async def test_is_required_and_not_skippable(self):
        step = example.PasswordlessRegisterStep()
        assert step.skippable is False
        assert await step.is_required(_make_context({})) is True


class TestMandatoryRegisterPasskeyStep:
    async def test_step_is_required_and_not_skippable(self):
        step = example.MandatoryRegisterPasskeyStep(example.passkey_service)
        context = _make_context({})
        assert step.skippable is False
        assert await step.is_required(context) is True

    async def test_shares_challenge_backend_across_phases(self):
        """Regression: the step must use a single PasskeyService so the
        in-memory challenge stored at begin is visible at complete.
        Previously each phase instantiated its own PasskeyService (with a
        per-instance InMemoryChallengeBackend), causing "Challenge expired
        or not found" errors at complete.
        """
        from unittest.mock import MagicMock, patch

        user = example.User(email="regression@example.com")
        user.set_unusable_password()
        await user.save()

        step = example.MandatoryRegisterPasskeyStep(example.passkey_service)
        context = StepContext(
            session_id="sid",
            step_data={},
            user_id=str(user.pk),
            config=example.config,
        )

        # Phase 1: begin registration — stores a real challenge in the
        # service's in-memory backend.
        opts = MagicMock()
        opts.challenge = b"fake-challenge-bytes-1234567890"
        with (
            patch("webauthn.generate_registration_options", return_value=opts),
            patch("webauthn.options_to_json", return_value='{"mock": true}'),
        ):
            begin = await step.execute(context, {})

        assert begin.success is True
        assert begin.completed is False
        challenge_id = begin.data["_passkey_challenge_id"]

        # Confirm the challenge landed in the shared backend
        stored = await example.passkey_service.challenge_backend.retrieve(challenge_id)
        assert stored is not None, (
            "Challenge missing from shared backend — step is not reusing "
            "the module-level PasskeyService"
        )

        # Phase 2: complete registration — must find the same challenge.
        fake_verification = MagicMock(
            credential_id=b"\x01\x02\x03",
            credential_public_key=b"\xaa\xbb",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type="multi_device",
            credential_backed_up=True,
        )
        context2 = StepContext(
            session_id="sid",
            step_data={"_passkey_challenge_id": challenge_id},
            user_id=str(user.pk),
            config=example.config,
        )
        cred = {
            "id": "AQID",
            "rawId": "AQID",
            "type": "public-key",
            "response": {"attestationObject": "x", "clientDataJSON": "y"},
        }
        with patch(
            "webauthn.verify_registration_response", return_value=fake_verification
        ):
            complete = await step.execute(context2, {"credential": cred, "name": "k"})

        assert complete.success is True, complete.errors
        assert complete.data == {"passkey_registered": True}


class TestOnboardingPipeline:
    async def test_invitation_flow_creates_passwordless_user(self):
        """End-to-end up to (but not including) passkey registration."""
        token = await example.invitation_service.create_invitation(
            "carol@example.com", invited_by="admin", role="editor"
        )

        started = await example.onboarding_service.start("placeholder@invite.local")
        assert started.current_step == "validate_invitation"

        validated = await example.onboarding_service.advance(
            started.session_token, {"invitation_token": token}
        )
        assert validated.status == "in_progress"
        assert validated.current_step == "register_passwordless"
        assert validated.step_result is not None
        assert validated.step_result.data["email"] == "carol@example.com"

        registered = await example.onboarding_service.advance(
            started.session_token, {}
        )
        assert registered.status == "in_progress"
        assert registered.current_step == "register_passkey"

        user = await example.User.filter(email="carol@example.com").first()
        assert user is not None
        assert user.has_usable_password() is False

    async def test_invalid_invitation_token_blocks_pipeline(self):
        started = await example.onboarding_service.start("placeholder@invite.local")
        result = await example.onboarding_service.advance(
            started.session_token, {"invitation_token": "not-a-real-token"}
        )
        assert result.status == "error"
        assert result.step_result is not None
        assert not result.step_result.success
        assert await example.User.filter(email__contains="@").count() == 0


class TestStarletteEndpointsCanHitTortoise:
    """Regression test: request-handler tasks must see DB connections created
    by Tortoise.init() in the lifespan task. Driven through ASGITransport so
    we're exercising the same code path as uvicorn."""

    async def test_onboarding_start_succeeds(self):
        transport = ASGITransport(example.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/onboarding/start", json={"email": "placeholder@invite.local"}
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "in_progress"
        assert body["current_step"] == "validate_invitation"
        assert body["session_token"]

    async def test_onboarding_advance_rejects_bad_token(self):
        transport = ASGITransport(example.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start = await client.post(
                "/onboarding/start", json={"email": "placeholder@invite.local"}
            )
            session_token = start.json()["session_token"]

            resp = await client.post(
                "/onboarding/advance",
                json={"session_token": session_token, "data": {"invitation_token": "garbage"}},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "error"
        assert body["step_result"]["success"] is False


class TestCookieAuthFlow:
    """Regression: ``/admin`` must be reachable after a passkey login without
    the client manually attaching an ``Authorization`` header. Previously the
    access token was only returned in the JSON body and stored in
    sessionStorage, so a plain ``location.href = "/admin"`` navigation had no
    auth and got redirected back to ``/login``.
    """

    async def _login_and_get_cookie(self, client):
        from unittest.mock import MagicMock, patch

        user = example.User(email="cookie-user@example.com", is_active=True)
        user.set_unusable_password()
        await user.save()

        # Register a passkey directly in the DB so authenticate can find it.
        from tortoise_auth.models.passkey import PasskeyCredential
        from base64 import urlsafe_b64encode

        cred_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        cred_id_b64 = urlsafe_b64encode(cred_id).rstrip(b"=").decode()
        await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=cred_id,
            credential_id_b64=cred_id_b64,
            public_key=b"\xaa\xbb",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type="multi_device",
            credential_backed_up=True,
            name="test-key",
            transports="",
        )

        fake_auth_opts = MagicMock()
        fake_auth_opts.challenge = b"fake-auth-challenge-1234567890"
        fake_verification = MagicMock(
            credential_id=cred_id,
            new_sign_count=1,
            credential_device_type="multi_device",
            credential_backed_up=True,
            user_verified=True,
        )

        cred_response = {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "authenticatorData": "x",
                "clientDataJSON": "y",
                "signature": "z",
            },
        }

        with (
            patch(
                "webauthn.generate_authentication_options",
                return_value=fake_auth_opts,
            ),
            patch("webauthn.options_to_json", return_value='{"mock": true}'),
            patch(
                "webauthn.verify_authentication_response",
                return_value=fake_verification,
            ),
        ):
            begin = await client.post("/passkey/authenticate/begin", json={})
            challenge_id = begin.json()["challenge_id"]
            complete = await client.post(
                "/passkey/authenticate/complete",
                json={"challenge_id": challenge_id, "credential": cred_response},
            )
        assert complete.status_code == 200
        return complete

    async def test_login_sets_cookie_and_admin_is_accessible(self):
        transport = ASGITransport(example.app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await self._login_and_get_cookie(client)

            # Cookie must be set, httpOnly-like (starlette sets it httponly).
            assert example.ACCESS_COOKIE in resp.cookies
            assert resp.cookies[example.ACCESS_COOKIE]

            # Navigating to /admin on the same client (cookies preserved)
            # must now succeed — no manual Authorization header.
            admin = await client.get("/admin")
        assert admin.status_code == 200, (
            f"/admin should be reachable via the access cookie after login, "
            f"got {admin.status_code} (redirect target: "
            f"{admin.headers.get('location')})"
        )
        assert b"Admin Dashboard" in admin.content

    async def test_admin_redirects_to_login_without_cookie(self):
        transport = ASGITransport(example.app)
        async with AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            admin = await client.get("/admin")
        assert admin.status_code == 302
        assert admin.headers["location"] == "/login"

    async def test_logout_clears_cookie(self):
        transport = ASGITransport(example.app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            await self._login_and_get_cookie(client)
            assert example.ACCESS_COOKIE in client.cookies

            resp = await client.post("/auth/logout")
            assert resp.status_code == 200
            # Starlette's delete_cookie sets Max-Age=0, which httpx honors.
            assert client.cookies.get(example.ACCESS_COOKIE) in (None, "")

            # /admin must now redirect again.
            admin = await client.get("/admin", follow_redirects=False)
        assert admin.status_code == 302


class TestInviteCLI:
    async def test_create_invitation_and_format_link(self):
        """Exercises the same service call the CLI uses and asserts the
        link format."""
        token = await example.invitation_service.create_invitation(
            "dan@example.com", invited_by="admin", role=""
        )
        link = f"{example.PUBLIC_BASE_URL}/onboarding?token={token}"

        assert link.startswith("http://localhost:8000/onboarding?token=")
        assert token in link

        # Token should validate through the same service the webapp uses
        invitation = await example.invitation_service.validate_invitation(token)
        assert invitation.email == "dan@example.com"