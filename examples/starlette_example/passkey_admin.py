"""
Starlette example: Passwordless admin dashboard with invitation-only onboarding.

This example shows:
- Invitation-only access, created via a CLI (``invite.py``) that prints a link
- Passwordless onboarding: validate invitation → create account → register passkey
- Passkey-based login (the only way to sign in)
- Admin dashboard with read-only invitation list and passkey management

Run:
    pip install tortoise-auth[starlette,passkey] uvicorn
    uvicorn examples.starlette_example.passkey_admin:app --reload

Then create the first invitation (bootstrap admin) with:
    python -m examples.starlette_example.invite admin@example.com
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from tortoise import Tortoise, fields
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from tortoise_auth import (
    AuthConfig,
    AuthService,
    InvitationService,
    OnboardingService,
    PasskeyService,
    RegisterPasskeyStep,
    ValidateInvitationStep,
    configure,
)
from tortoise_auth.exceptions import AuthenticationError, TokenError
from tortoise_auth.integrations.starlette import (
    AnonymousUser,
    TokenAuthBackend,
    login_required,
    require_auth,
)
from tortoise_auth.models import AbstractUser
from tortoise_auth.onboarding import ClientHint, StepContext, StepResult
from tortoise_auth.tokens.jwt import JWTBackend


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class User(AbstractUser):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "users"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
config = AuthConfig(
    user_model="models.User",
    signing_secret="change-me-to-a-real-signing-secret-32-bytes!!",
    jwt_secret="change-me-to-a-real-secret-at-least-32-bytes!!",
    jwt_blacklist_enabled=True,
    # Passkey
    passkey_rp_id="localhost",
    passkey_rp_name="Admin Dashboard",
    passkey_origin="http://localhost:8000",
    # Invitation-only registration
    invitation_require=True,
    invitation_token_lifetime=86_400,  # 24 hours
)
configure(config)

PUBLIC_BASE_URL = "http://localhost:8000"
ACCESS_COOKIE = "access_token"
COOKIE_MAX_AGE = 60 * 60 * 8  # 8 hours

jwt_backend = JWTBackend(config)
auth_service = AuthService(config, backend=jwt_backend)
passkey_service = PasskeyService(config, backend=jwt_backend)
invitation_service = InvitationService(config)


class CookieTokenAuthBackend(TokenAuthBackend):
    """Extends the Bearer-token backend to also accept a JWT from a cookie.

    Browser navigations (e.g. ``location.href = "/admin"``) can't attach an
    ``Authorization`` header. Storing the JWT in an httpOnly cookie lets
    server-rendered pages authenticate on normal navigation while keeping the
    token invisible to JavaScript (XSS-resistant).
    """

    async def authenticate(self, conn: HTTPConnection):
        header_result = await super().authenticate(conn)
        _, user = header_result
        if getattr(user, "is_authenticated", False):
            return header_result

        token = conn.cookies.get(ACCESS_COOKIE)
        if not token:
            return AuthCredentials([]), AnonymousUser()

        try:
            user = await self.auth_service.authenticate(token)
        except (TokenError, AuthenticationError):
            return AuthCredentials([]), AnonymousUser()
        return AuthCredentials(["authenticated"]), user


def _set_access_cookie(response: Response, access_token: str) -> None:
    """Attach the access token as an httpOnly cookie.

    ``secure=False`` is appropriate for a localhost dev example; in production
    this should be True and the site served over HTTPS.
    """
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


# ---------------------------------------------------------------------------
# Custom onboarding steps — passwordless
# ---------------------------------------------------------------------------
class PasswordlessRegisterStep:
    """Creates a user with an unusable password (passkey-only accounts).

    Assumes ValidateInvitationStep ran first and put ``email`` in step_data.
    """

    @property
    def name(self) -> str:
        return "register_passwordless"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        email = context.step_data.get("email", "").strip()
        if not email:
            return StepResult(
                success=False,
                errors=["Missing invitation email — validate the invitation first"],
            )

        user_model = _resolve_user_model(context.config.user_model)
        existing = await user_model.filter(email=email).first()
        if existing is not None:
            return StepResult(success=True, data={"user_id": str(existing.pk)})

        user = user_model(email=email, is_active=True, is_verified=True)
        user.set_unusable_password()
        await user.save()
        return StepResult(success=True, data={"user_id": str(user.pk)})

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(
            step_name=self.name,
            title="Confirm your account",
            description=(
                f"You're creating an account for "
                f"{context.step_data.get('email', '')}. "
                "No password needed — you'll use a passkey."
            ),
            fields=[],
        )


class MandatoryRegisterPasskeyStep(RegisterPasskeyStep):
    """Same as RegisterPasskeyStep but required — no passkey means no access.

    Also wires the step to a shared :class:`PasskeyService` so the WebAuthn
    challenge stored during ``begin_registration`` is retrievable during
    ``complete_registration``. The default parent implementation spins up a
    fresh service per phase, and its :class:`InMemoryChallengeBackend` is
    per-instance — resulting in a ``Challenge expired or not found`` error at
    the complete step.
    """

    def __init__(self, service: PasskeyService) -> None:
        self._service = service

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def _begin_registration(self, context: StepContext) -> StepResult:
        user_id = context.user_id
        if not user_id:
            return StepResult(success=False, errors=["User not created yet"])

        user_model = _resolve_user_model(context.config.user_model)
        user = await user_model.filter(pk=user_id).first()
        if not user:
            return StepResult(success=False, errors=["User not found"])

        result = await self._service.begin_registration(user)
        return StepResult(
            success=True,
            completed=False,
            data={
                "_passkey_options": result["options"],
                "_passkey_challenge_id": result["challenge_id"],
            },
        )

    async def _complete_registration(
        self, context: StepContext, data: dict[str, Any]
    ) -> StepResult:
        user_id = context.user_id
        if not user_id:
            return StepResult(success=False, errors=["User not created yet"])

        user_model = _resolve_user_model(context.config.user_model)
        user = await user_model.filter(pk=user_id).first()
        if not user:
            return StepResult(success=False, errors=["User not found"])

        challenge_id = context.step_data.get("_passkey_challenge_id", "")
        if not challenge_id:
            return StepResult(success=False, errors=["No registration in progress"])

        try:
            await self._service.complete_registration(
                user,
                credential=data["credential"],
                challenge_id=challenge_id,
                name=data.get("name", ""),
            )
        except Exception as exc:
            return StepResult(success=False, errors=[str(exc)])

        return StepResult(success=True, data={"passkey_registered": True})


def _resolve_user_model(model_path: str) -> Any:
    app_label, model_name = model_path.rsplit(".", 1)
    return Tortoise.apps[app_label][model_name]


onboarding_service = OnboardingService(
    config,
    steps={
        "validate_invitation": ValidateInvitationStep(),
        "register_passwordless": PasswordlessRegisterStep(),
        "register_passkey": MandatoryRegisterPasskeyStep(passkey_service),
    },
    pipeline=["validate_invitation", "register_passwordless", "register_passkey"],
)


# ---------------------------------------------------------------------------
# Routes — Onboarding (invitation-based, passwordless)
# ---------------------------------------------------------------------------
async def onboarding_page(request: Request) -> HTMLResponse:
    """GET /onboarding?token=... — accept an invitation and register a passkey."""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head><title>Accept Invitation</title></head>
    <body>
        <h1>Welcome</h1>

        <div id="step-invitation">
            <h2>Step 1: Your invitation</h2>
            <p>Paste the token from your invitation link, or open the full link.</p>
            <form id="invitation-form">
                <input name="invitation_token" id="token-input"
                       placeholder="Invitation token" required style="width:400px">
                <button type="submit">Validate</button>
            </form>
        </div>

        <div id="step-confirm" style="display:none">
            <h2>Step 2: Confirm account</h2>
            <p>Account will be created for: <strong id="confirm-email"></strong></p>
            <p>No password needed — the next step registers your passkey.</p>
            <button id="confirm-button">Create account</button>
        </div>

        <div id="step-passkey" style="display:none">
            <h2>Step 3: Register your passkey</h2>
            <p>This is the only way you'll sign in. Use your device's biometrics,
               PIN, or a security key.</p>
            <input id="passkey-name" placeholder="Name this passkey"
                   value="My primary device">
            <button id="passkey-button">Register passkey</button>
        </div>

        <div id="step-complete" style="display:none">
            <h2>You're in!</h2>
            <p>Redirecting to the admin dashboard...</p>
        </div>

        <p id="status" style="color:red"></p>

        <script>
        let sessionToken = null;
        const status = document.getElementById("status");

        // Pre-fill token from ?token= in URL so the invitation link is one-click
        const urlToken = new URLSearchParams(location.search).get("token");
        if (urlToken) {
            document.getElementById("token-input").value = urlToken;
        }

        // --- Helpers for base64url <-> Uint8Array ---
        const b64uToBytes = (s) => Uint8Array.from(
            atob(s.replace(/-/g,"+").replace(/_/g,"/")),
            c => c.charCodeAt(0)
        );
        const bytesToB64u = (buf) =>
            btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=/g,"");

        async function advance(data) {
            const resp = await fetch("/onboarding/advance", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({session_token: sessionToken, data}),
            });
            return resp.json();
        }

        // --- Step 1: validate invitation token ---
        document.getElementById("invitation-form").onsubmit = async (e) => {
            e.preventDefault();
            status.textContent = "";
            const token = new FormData(e.target).get("invitation_token");

            const startResp = await fetch("/onboarding/start", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({email: "placeholder@invite.local"}),
            });
            if (!startResp.ok) {
                status.textContent = "Failed to start onboarding";
                return;
            }
            sessionToken = (await startResp.json()).session_token;

            const advData = await advance({invitation_token: token});
            if (advData.status === "error") {
                status.textContent = advData.step_result?.errors?.join(", ")
                    || "Invalid invitation";
                return;
            }
            document.getElementById("confirm-email").textContent =
                advData.step_result?.data?.email || "";
            document.getElementById("step-invitation").style.display = "none";
            document.getElementById("step-confirm").style.display = "block";
        };

        // --- Step 2: confirm account (creates user with unusable password) ---
        document.getElementById("confirm-button").onclick = async () => {
            status.textContent = "";
            const advData = await advance({});
            if (advData.status === "error") {
                status.textContent = advData.step_result?.errors?.join(", ")
                    || "Account creation failed";
                return;
            }
            // Server advances to register_passkey and returns options
            document.getElementById("step-confirm").style.display = "none";
            document.getElementById("step-passkey").style.display = "block";
        };

        // --- Step 3: register passkey (mandatory) ---
        document.getElementById("passkey-button").onclick = async () => {
            status.textContent = "";
            // Phase 1: ask server for WebAuthn options
            const begin = await advance({});
            const extra = begin.client_hint?.extra;
            if (!extra?.options) {
                status.textContent = "Failed to begin passkey registration";
                return;
            }
            const options = JSON.parse(extra.options);
            options.challenge = b64uToBytes(options.challenge);
            options.user.id = b64uToBytes(options.user.id);
            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(c => ({
                    ...c, id: b64uToBytes(c.id),
                }));
            }

            let credential;
            try {
                credential = await navigator.credentials.create({publicKey: options});
            } catch (e) {
                status.textContent = "Passkey creation cancelled: " + e.message;
                return;
            }

            // Phase 2: send credential back
            const name = document.getElementById("passkey-name").value || "My passkey";
            const body = {
                name,
                credential: {
                    id: credential.id,
                    rawId: bytesToB64u(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bytesToB64u(
                            credential.response.attestationObject),
                        clientDataJSON: bytesToB64u(
                            credential.response.clientDataJSON),
                    },
                },
            };
            const final = await advance(body);
            if (final.status === "completed" && final.auth_result) {
                // Access token is also set as an httpOnly cookie by the server,
                // so the browser will send it on navigation to /admin.
                document.getElementById("step-passkey").style.display = "none";
                document.getElementById("step-complete").style.display = "block";
                setTimeout(() => location.href = "/admin", 1200);
            } else {
                status.textContent = final.step_result?.errors?.join(", ")
                    || "Passkey registration failed";
            }
        };
        </script>
    </body>
    </html>
    """)


async def onboarding_start(request: Request) -> JSONResponse:
    """POST /onboarding/start  { "email": "..." }"""
    body = await request.json()
    result = await onboarding_service.start(body.get("email", ""))
    return JSONResponse({
        "session_token": result.session_token,
        "current_step": result.current_step,
        "status": result.status,
    })


async def onboarding_advance(request: Request) -> JSONResponse:
    """POST /onboarding/advance  { "session_token": "...", "data": {...} }"""
    body = await request.json()
    result = await onboarding_service.advance(body["session_token"], body.get("data", {}))
    response = JSONResponse({
        "session_token": body["session_token"],
        "current_step": result.current_step,
        "status": result.status,
        "step_result": {
            "success": result.step_result.success,
            "errors": result.step_result.errors,
            "data": result.step_result.data,
        } if result.step_result else None,
        "auth_result": {
            "access_token": result.auth_result.access_token,
            "refresh_token": result.auth_result.refresh_token,
        } if result.auth_result else None,
        "client_hint": {
            "step_name": result.client_hint.step_name,
            "title": result.client_hint.title,
            "fields": [
                {"name": f.name, "type": f.field_type, "required": f.required}
                for f in result.client_hint.fields
            ],
            "extra": result.client_hint.extra,
        } if result.client_hint else None,
    })
    if result.auth_result is not None:
        _set_access_cookie(response, result.auth_result.access_token)
    return response


# ---------------------------------------------------------------------------
# Routes — Invitation listing (read-only; creation is CLI-only)
# ---------------------------------------------------------------------------
@login_required
async def invitation_list(request: Request) -> JSONResponse:
    """GET /admin/invitations — list pending invitations."""
    require_auth(request)
    pending = await invitation_service.list_pending()
    return JSONResponse([
        {
            "id": inv.id,
            "email": inv.email,
            "role": inv.role,
            "created_at": str(inv.created_at),
            "expires_at": str(inv.expires_at),
        }
        for inv in pending
    ])


@login_required
async def invitation_revoke(request: Request) -> JSONResponse:
    """DELETE /admin/invitations/{invitation_id}"""
    require_auth(request)
    invitation_id = int(request.path_params["invitation_id"])
    await invitation_service.revoke_invitation(invitation_id)
    return JSONResponse({"revoked": True})


# ---------------------------------------------------------------------------
# Routes — Passkey management (post-signup, from the dashboard)
# ---------------------------------------------------------------------------
@login_required
async def passkey_register_begin(request: Request) -> JSONResponse:
    user = require_auth(request)
    result = await passkey_service.begin_registration(user)
    return JSONResponse({"options": result["options"], "challenge_id": result["challenge_id"]})


@login_required
async def passkey_register_complete(request: Request) -> JSONResponse:
    user = require_auth(request)
    body = await request.json()
    passkey = await passkey_service.complete_registration(
        user,
        credential=body["credential"],
        challenge_id=body["challenge_id"],
        name=body.get("name", ""),
    )
    return JSONResponse({
        "id": passkey.credential_id_b64,
        "name": passkey.name,
        "created_at": str(passkey.created_at),
    })


@login_required
async def passkey_list(request: Request) -> JSONResponse:
    user = require_auth(request)
    creds = await passkey_service.list_credentials(user)
    return JSONResponse([
        {
            "id": c.credential_id_b64,
            "name": c.name,
            "device_type": c.credential_device_type,
            "backed_up": c.credential_backed_up,
            "created_at": str(c.created_at),
            "last_used_at": str(c.last_used_at) if c.last_used_at else None,
        }
        for c in creds
    ])


@login_required
async def passkey_delete(request: Request) -> JSONResponse:
    user = require_auth(request)
    credential_id = request.path_params["credential_id"]
    # Guard: refuse to delete the last passkey — user would be locked out
    creds = await passkey_service.list_credentials(user)
    if len(creds) <= 1:
        return JSONResponse(
            {"error": "Cannot delete your last passkey"}, status_code=400
        )
    await passkey_service.delete_credential(user, credential_id)
    return JSONResponse({"deleted": True})


# ---------------------------------------------------------------------------
# Routes — Passkey authentication (public login)
# ---------------------------------------------------------------------------
async def passkey_auth_begin(request: Request) -> JSONResponse:
    result = await passkey_service.begin_authentication()
    return JSONResponse({"options": result["options"], "challenge_id": result["challenge_id"]})


async def passkey_auth_complete(request: Request) -> JSONResponse:
    body = await request.json()
    result = await passkey_service.complete_authentication(
        credential=body["credential"],
        challenge_id=body["challenge_id"],
    )
    response = JSONResponse({
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "user_email": result.user.email,
    })
    _set_access_cookie(response, result.access_token)
    return response


async def logout(request: Request) -> JSONResponse:
    """POST /auth/logout — clears the access cookie."""
    response = JSONResponse({"ok": True})
    response.delete_cookie(ACCESS_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# Routes — Admin dashboard
# ---------------------------------------------------------------------------
@login_required(redirect_url="/login")
async def admin_dashboard(request: Request) -> HTMLResponse:
    user = request.user
    creds = await passkey_service.list_credentials(user)
    pending_invitations = await invitation_service.list_pending()

    q = "'"
    if creds:
        passkey_items = "".join(
            f"<li>{c.name or 'Unnamed'} — {c.credential_device_type} "
            f"(last used: {c.last_used_at or 'never'})"
            f" <button onclick=\"deletePasskey({q}{c.credential_id_b64}{q})\">Delete</button></li>"
            for c in creds
        )
    else:
        passkey_items = "<li>No passkeys registered</li>"

    if pending_invitations:
        invitation_items = "".join(
            f"<li>{inv.email}"
            f"{' (' + inv.role + ')' if inv.role else ''}"
            f" — expires {inv.expires_at:%Y-%m-%d %H:%M}"
            f" <button onclick=\"revokeInvitation({inv.id})\">Revoke</button></li>"
            for inv in pending_invitations
        )
    else:
        invitation_items = "<li>No pending invitations</li>"

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head><title>Admin Dashboard</title></head>
    <body>
        <h1>Admin Dashboard</h1>
        <p>Welcome, <strong>{user.email}</strong>
           <button id="logout-button" style="margin-left:1em">Sign out</button></p>
        <hr>

        <h2>Pending invitations</h2>
        <p><em>Create new invitations from the CLI:</em>
           <code>python -m examples.starlette_example.invite &lt;email&gt;</code></p>
        <ul id="invitation-list">
            {invitation_items}
        </ul>
        <hr>

        <h2>Your passkeys ({len(creds)})</h2>
        <button id="register-passkey">Add passkey</button>
        <p id="register-status"></p>
        <ul id="passkey-list">
            {passkey_items}
        </ul>

        <script>
        // All fetches below rely on the httpOnly access_token cookie
        // (same-origin => sent automatically). No Authorization header needed.
        const headers = {{"Content-Type": "application/json"}};

        document.getElementById("logout-button").onclick = async () => {{
            await fetch("/auth/logout", {{method: "POST", headers}});
            location.href = "/login";
        }};

        const b64uToBytes = (s) => Uint8Array.from(
            atob(s.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
        const bytesToB64u = (buf) =>
            btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=/g,"");

        async function revokeInvitation(id) {{
            if (!confirm("Revoke this invitation?")) return;
            await fetch("/admin/invitations/" + id, {{method: "DELETE", headers}});
            location.reload();
        }}

        document.getElementById("register-passkey").onclick = async () => {{
            const status = document.getElementById("register-status");
            try {{
                const beginResp = await fetch("/passkey/register/begin",
                    {{method: "POST", headers}});
                const begin = await beginResp.json();
                const options = JSON.parse(begin.options);
                options.challenge = b64uToBytes(options.challenge);
                options.user.id = b64uToBytes(options.user.id);
                if (options.excludeCredentials) {{
                    options.excludeCredentials = options.excludeCredentials.map(c => ({{
                        ...c, id: b64uToBytes(c.id),
                    }}));
                }}

                const credential = await navigator.credentials.create(
                    {{publicKey: options}});
                const body = {{
                    challenge_id: begin.challenge_id,
                    name: prompt("Name this passkey:", "My passkey") || "My passkey",
                    credential: {{
                        id: credential.id,
                        rawId: bytesToB64u(credential.rawId),
                        type: credential.type,
                        response: {{
                            attestationObject: bytesToB64u(
                                credential.response.attestationObject),
                            clientDataJSON: bytesToB64u(
                                credential.response.clientDataJSON),
                        }},
                    }},
                }};
                const completeResp = await fetch("/passkey/register/complete",
                    {{method: "POST", headers, body: JSON.stringify(body)}});
                if (completeResp.ok) {{
                    status.textContent = "Passkey registered! Reloading...";
                    location.reload();
                }} else {{
                    status.textContent = "Error: "
                        + (await completeResp.json()).detail;
                }}
            }} catch (e) {{
                status.textContent = "Error: " + e.message;
            }}
        }};

        async function deletePasskey(id) {{
            if (!confirm("Delete this passkey?")) return;
            const resp = await fetch("/passkey/credentials/" + id,
                {{method: "DELETE", headers}});
            if (!resp.ok) {{
                const err = await resp.json();
                alert(err.error || "Failed to delete");
                return;
            }}
            location.reload();
        }}
        </script>
    </body>
    </html>
    """)


async def login_page(request: Request) -> HTMLResponse:
    """GET /login — passkey-only login page."""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Sign in with your passkey</h1>
        <button id="passkey-login">Login with passkey</button>
        <p id="status"></p>
        <p><a href="/onboarding">Have an invitation? Accept it here.</a></p>

        <script>
        const status = document.getElementById("status");
        const b64uToBytes = (s) => Uint8Array.from(
            atob(s.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
        const bytesToB64u = (buf) =>
            btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=/g,"");

        document.getElementById("passkey-login").onclick = async () => {
            try {
                const beginResp = await fetch("/passkey/authenticate/begin", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                });
                const begin = await beginResp.json();
                const options = JSON.parse(begin.options);
                options.challenge = b64uToBytes(options.challenge);
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(c => ({
                        ...c, id: b64uToBytes(c.id),
                    }));
                }

                const assertion = await navigator.credentials.get(
                    {publicKey: options});
                const body = {
                    challenge_id: begin.challenge_id,
                    credential: {
                        id: assertion.id,
                        rawId: bytesToB64u(assertion.rawId),
                        type: assertion.type,
                        response: {
                            authenticatorData: bytesToB64u(
                                assertion.response.authenticatorData),
                            clientDataJSON: bytesToB64u(
                                assertion.response.clientDataJSON),
                            signature: bytesToB64u(assertion.response.signature),
                            userHandle: assertion.response.userHandle
                                ? bytesToB64u(assertion.response.userHandle)
                                : null,
                        },
                    },
                };
                const completeResp = await fetch("/passkey/authenticate/complete", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify(body),
                });
                if (completeResp.ok) {
                    const data = await completeResp.json();
                    // Server also set an httpOnly access_token cookie.
                    status.textContent = "Welcome " + data.user_email + "!";
                    location.href = "/admin";
                } else {
                    status.textContent = "Passkey login failed";
                }
            } catch (e) {
                status.textContent = "Error: " + e.message;
            }
        };
        </script>
    </body>
    </html>
    """)


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
TORTOISE_MODULES = {
    "models": [
        "examples.starlette_example.passkey_admin",
        "tortoise_auth.models.invitation",
        "tortoise_auth.models.jwt_blacklist",
        "tortoise_auth.models.onboarding",
        "tortoise_auth.models.passkey",
        "tortoise_auth.models.tokens",
    ]
}
TORTOISE_DB_URL = "sqlite://db.sqlite3"


async def on_startup() -> None:
    # _enable_global_fallback=True is required so the Tortoise connections
    # registered in this lifespan task are visible from request-handler tasks.
    await Tortoise.init(
        db_url=TORTOISE_DB_URL,
        modules=TORTOISE_MODULES,
        _enable_global_fallback=True,
    )
    await Tortoise.generate_schemas()

    if not await User.exists() and not await invitation_service.list_pending():
        print()
        print("=" * 72)
        print("No users and no pending invitations found.")
        print("Bootstrap the first admin with:")
        print("    python -m examples.starlette_example.invite admin@example.com")
        print("=" * 72)
        print()


@asynccontextmanager
async def lifespan(app: Starlette):
    await on_startup()
    yield
    await Tortoise.close_connections()


app = Starlette(
    routes=[
        # Public pages
        Route("/login", login_page),
        Route("/onboarding", onboarding_page),
        # Onboarding API
        Route("/onboarding/start", onboarding_start, methods=["POST"]),
        Route("/onboarding/advance", onboarding_advance, methods=["POST"]),
        # Passkey auth (public)
        Route("/passkey/authenticate/begin", passkey_auth_begin, methods=["POST"]),
        Route("/passkey/authenticate/complete", passkey_auth_complete, methods=["POST"]),
        # Logout
        Route("/auth/logout", logout, methods=["POST"]),
        # Passkey management (requires auth)
        Route("/passkey/register/begin", passkey_register_begin, methods=["POST"]),
        Route("/passkey/register/complete", passkey_register_complete, methods=["POST"]),
        Route("/passkey/credentials", passkey_list),
        Route("/passkey/credentials/{credential_id}", passkey_delete, methods=["DELETE"]),
        # Invitation listing/revocation (creation is CLI-only)
        Route("/admin/invitations", invitation_list),
        Route("/admin/invitations/{invitation_id:int}", invitation_revoke, methods=["DELETE"]),
        # Protected admin
        Route("/admin", admin_dashboard),
    ],
    lifespan=lifespan,
)

app.add_middleware(
    AuthenticationMiddleware,
    backend=CookieTokenAuthBackend(auth_service=auth_service),
)