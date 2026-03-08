# Onboarding Flow

tortoise-auth provides a **server-driven onboarding flow engine** that guides
users through multi-step registration. Instead of orchestrating register →
verify email → setup TOTP via separate API calls, you expose a single endpoint
and let the server tell the client what to render at each step.

The engine is inspired by Clerk, WorkOS, and Stytch — but runs entirely within
your Tortoise ORM stack with no external dependencies.

## Quick Start

```python
from tortoise_auth import AuthConfig, OnboardingService
from tortoise_auth.onboarding.steps import RegisterStep, VerifyEmailStep

config = AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    jwt_secret="your-jwt-secret",
)

service = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
    },
    pipeline=["register", "verify_email"],
)

# Start a new onboarding flow
result = await service.start("user@example.com")
print(result.session_token)   # give this to the client
print(result.client_hint)     # tells the client what form to render
```

## How It Works

The onboarding flow is a **state machine** stored in the database:

1. **`start(email)`** — creates an `OnboardingSession`, finds the first required
   step, and returns a `client_hint` describing what the client should display.

2. **`advance(session_token, data)`** — executes the current step with the
   submitted data. On success, moves to the next step. On failure, returns
   errors and the same `client_hint` for retry.

3. **`resume(session_token)`** — returns the current step's `client_hint`
   without executing anything. Use this when the user returns after closing
   their browser.

4. When all steps are complete, `advance()` calls `_finalize()` which issues
   auth tokens via `AuthService` and returns an `OnboardingResult` with
   `status="completed"` and an `auth_result` containing `access_token` and
   `refresh_token`.

The client **never** needs to know the list of steps in advance. It simply
reacts to the `client_hint` returned by the server.

```text
Client                          Server
  │                               │
  │  POST /onboarding/start       │
  │  { email }                    │
  │──────────────────────────────>│
  │                               │  create session
  │  { client_hint: register }    │  find first step
  │<──────────────────────────────│
  │                               │
  │  POST /onboarding/advance     │
  │  { email, password, ... }     │
  │──────────────────────────────>│
  │                               │  execute register step
  │  { client_hint: verify_email }│  move to next step
  │<──────────────────────────────│
  │                               │
  │  POST /onboarding/advance     │
  │  { }  (triggers code send)    │
  │──────────────────────────────>│
  │                               │  emit verification_code_generated
  │  { client_hint: code input }  │
  │<──────────────────────────────│
  │                               │
  │  POST /onboarding/advance     │
  │  { code: "123456" }           │
  │──────────────────────────────>│
  │                               │  verify code, finalize
  │  { status: completed,         │  issue tokens
  │    auth_result: { tokens } }  │
  │<──────────────────────────────│
```

## Configuration

All onboarding settings are part of `AuthConfig`:

| Option | Default | Description |
|--------|---------|-------------|
| `onboarding_session_lifetime` | `3600` | Session lifetime in seconds (1 hour) |
| `onboarding_session_token_length` | `64` | Length of the session token |
| `onboarding_require_totp` | `False` | Whether TOTP setup is required (not just offered) |
| `onboarding_max_verification_attempts` | `5` | Max wrong verification codes before session is invalidated |
| `onboarding_verification_code_ttl` | `600` | Verification code lifetime in seconds (10 minutes) |
| `onboarding_invalidate_previous_sessions` | `True` | Invalidate existing sessions for the same email on `start()` |

## Pipeline Configuration

The `pipeline` parameter controls the **order** of steps. The `steps` dict
provides the **implementations**. Only steps in the pipeline are executed.

### Register + Verify Email (minimal)

```python
service = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
    },
    pipeline=["register", "verify_email"],
)
```

### With Optional TOTP

```python
from tortoise_auth.onboarding.steps import SetupTOTPStep

config = AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    jwt_secret="your-jwt-secret",
    onboarding_require_totp=False,  # user can skip TOTP setup
)

service = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
        "setup_totp": SetupTOTPStep(),
    },
    pipeline=["register", "verify_email", "setup_totp"],
)
```

When `onboarding_require_totp=False`, `SetupTOTPStep` is skippable. The client
can call `advance(token, {}, skip=True)` to skip it.

When `onboarding_require_totp=True`, the step becomes required and cannot be
skipped.

### With Profile Completion

```python
from tortoise_auth.onboarding.steps import ProfileCompletionStep

service = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
        "profile": ProfileCompletionStep(
            required_fields=["first_name", "last_name"],
            optional_fields=["phone", "company"],
        ),
    },
    pipeline=["register", "verify_email", "profile"],
)
```

`ProfileCompletionStep` is automatically skippable when no `required_fields`
are configured.

## Built-in Steps

### RegisterStep

Creates a new user account. Validates email format, email uniqueness, password
strength (using the configured password validators), and password confirmation.

**Fields:** `email`, `password`, `password_confirm`

**Not skippable.** Always required.

### VerifyEmailStep

Two-phase email verification:

- **Phase 1** (no `code` in data): generates a signed 6-digit code and emits
  `verification_code_generated` — your application must send the email.
- **Phase 2** (`code` in data): verifies the code against the signed value
  and marks `user.is_verified = True`.

**Fields:** `code` (phase 2 only)

**Not skippable.** Required unless `step_data["email_verified"]` is already
`True`.

!!! warning "You must handle email sending"
    tortoise-auth does **not** send emails. Listen for the
    `verification_code_generated` event and send the code yourself:

    ```python
    from tortoise_auth import on

    @on("verification_code_generated")
    async def send_verification_email(*, email: str, code: str) -> None:
        await my_email_service.send(
            to=email,
            subject="Your verification code",
            body=f"Your code is: {code}",
        )
    ```

### SetupTOTPStep

Two-phase TOTP setup:

- **Phase 1** (no `code` in data): generates a TOTP secret and provisioning
  URI. The client can render a QR code from the URI.
- **Phase 2** (`code` in data): verifies the TOTP code and persists the
  secret on the user model (if the model has a `totp_secret` field).

**Fields:** `code` (phase 2 only)

**Skippable** (unless `onboarding_require_totp=True`).

Requires `pyotp` to be installed (`pip install pyotp`).

### ProfileCompletionStep

Collects additional profile fields and updates the user model. Configurable
at construction time via `required_fields` and `optional_fields`.

**Fields:** dynamic, based on constructor arguments.

**Skippable** when no `required_fields` are set.

## Custom Steps

Implement the `OnboardingStep` protocol to create your own steps:

```python
from tortoise_auth.onboarding import (
    ClientHint,
    FieldHint,
    OnboardingStep,
    StepContext,
    StepResult,
)


class AcceptTermsStep:
    @property
    def name(self) -> str:
        return "accept_terms"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def execute(
        self, context: StepContext, data: dict
    ) -> StepResult:
        if not data.get("accepted"):
            return StepResult(
                success=False,
                errors=["You must accept the terms of service"],
            )
        return StepResult(success=True, data={"terms_accepted": True})

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(
            step_name=self.name,
            title="Terms of Service",
            description="Please review and accept our terms.",
            fields=[
                FieldHint(
                    name="accepted",
                    field_type="checkbox",
                    label="I accept the terms of service",
                ),
            ],
            extra={"terms_url": "https://example.com/terms"},
        )
```

Then register it in your pipeline:

```python
service = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "accept_terms": AcceptTermsStep(),
        "verify_email": VerifyEmailStep(),
    },
    pipeline=["register", "accept_terms", "verify_email"],
)
```

### Multi-Phase Steps

For steps that require multiple interactions (like verify email or TOTP setup),
return `StepResult(success=True, completed=False)` from the intermediate
phases. This tells the service to merge `result.data` into the session's
`step_data` but stay on the same step.

```python
async def execute(self, context: StepContext, data: dict) -> StepResult:
    if "code" not in data:
        # Phase 1: generate something, stay on this step
        return StepResult(
            success=True,
            completed=False,
            data={"_generated_value": "..."},
        )
    # Phase 2: verify, complete the step
    return StepResult(success=True, data={"verified": True})
```

## Skipping Steps

Steps that have `skippable=True` can be skipped by the client:

```python
result = await service.advance(session_token, {}, skip=True)
```

Attempting to skip a non-skippable step returns an error:

```python
result = await service.advance(session_token, {}, skip=True)
assert result.status == "error"
assert "cannot be skipped" in result.step_result.errors[0]
```

## Session Management

### Resuming a Flow

If the user closes their browser and comes back:

```python
result = await service.resume(session_token)
# result.client_hint tells the client where they left off
```

### Session Expiration

Sessions expire after `onboarding_session_lifetime` seconds (default: 1 hour).
Expired sessions raise `OnboardingSessionExpiredError`:

```python
from tortoise_auth.exceptions import OnboardingSessionExpiredError

try:
    result = await service.advance(session_token, data)
except OnboardingSessionExpiredError:
    # prompt the user to start over
    ...
```

### Session Invalidation

By default, calling `start()` for an email that already has an active session
invalidates the previous session. This prevents session fixation attacks and
handles the case where a user starts over.

Disable this with `onboarding_invalidate_previous_sessions=False`.

### Cleanup

Delete expired sessions periodically:

```python
deleted = await service.cleanup_expired()
```

## Events

The onboarding engine emits lifecycle events that you can listen to:

| Event | Payload | When |
|-------|---------|------|
| `onboarding_started` | `email, session_id, pipeline` | `start()` creates a session |
| `onboarding_step_completed` | `session_id, step_name, user_id` | A step succeeds |
| `onboarding_step_skipped` | `session_id, step_name` | A step is skipped |
| `onboarding_step_failed` | `session_id, step_name, errors` | A step fails |
| `onboarding_completed` | `user, session_id` | All steps done, tokens issued |
| `onboarding_session_expired` | `session_id, email` | Expired session accessed |
| `verification_code_generated` | `email, code` | Verify email step generates a code |

```python
from tortoise_auth import on

@on("onboarding_completed")
async def welcome_user(*, user, session_id: str) -> None:
    await send_welcome_email(user.email)

@on("onboarding_step_failed")
async def log_failure(*, session_id: str, step_name: str, errors: list) -> None:
    logger.warning("Step %s failed for session %s: %s", step_name, session_id, errors)
```

## Database Setup

Register the onboarding model module in your Tortoise configuration:

```python
TORTOISE_ORM = {
    "apps": {
        "tortoise_auth": {
            "models": [
                "tortoise_auth.models.onboarding",
                # ... other model modules
            ],
        },
    },
}
```

This creates the `tortoise_auth_onboarding_sessions` table.

## Security

| Concern | How it's handled |
|---------|-----------------|
| **Session token storage** | SHA-256 hash stored in DB; raw token only on the client |
| **Session fixation** | `start()` invalidates previous sessions for the same email |
| **Brute-force verification codes** | Attempt counter; session invalidated after max attempts |
| **Code expiration** | Verification codes are signed with `TimestampSigner` and expire after `onboarding_verification_code_ttl` |
| **Expired sessions** | `is_valid` checks expiry on every `advance()` and `resume()` |
| **Concurrent sessions** | Only the most recent session for an email is valid |

## Error Handling

```python
from tortoise_auth.exceptions import (
    OnboardingError,
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
)

try:
    result = await service.advance(token, data)
except OnboardingSessionExpiredError:
    # 410 Gone — session expired, start over
    ...
except OnboardingSessionInvalidError:
    # 404 Not Found — session not found or invalidated
    ...
except OnboardingFlowCompleteError:
    # 409 Conflict — flow already completed
    ...
except OnboardingError:
    # catch-all for any onboarding error
    ...
```

## Full Example with Starlette

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tortoise_auth import AuthConfig, OnboardingService
from tortoise_auth.exceptions import (
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
)
from tortoise_auth.onboarding.steps import RegisterStep, VerifyEmailStep


config = AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    jwt_secret="your-jwt-secret",
)

onboarding = OnboardingService(
    config,
    steps={
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
    },
    pipeline=["register", "verify_email"],
)


async def start(request: Request) -> JSONResponse:
    body = await request.json()
    result = await onboarding.start(
        body["email"],
        ip_address=request.client.host,
    )
    return JSONResponse({
        "session_token": result.session_token,
        "current_step": result.current_step,
        "client_hint": _serialize_hint(result.client_hint),
    })


async def advance(request: Request) -> JSONResponse:
    body = await request.json()
    token = body.pop("session_token")
    skip = body.pop("skip", False)

    try:
        result = await onboarding.advance(token, body, skip=skip)
    except OnboardingSessionExpiredError:
        return JSONResponse({"error": "Session expired"}, status_code=410)
    except OnboardingSessionInvalidError:
        return JSONResponse({"error": "Session not found"}, status_code=404)
    except OnboardingFlowCompleteError:
        return JSONResponse({"error": "Already completed"}, status_code=409)

    response = {
        "status": result.status,
        "current_step": result.current_step,
        "client_hint": _serialize_hint(result.client_hint),
        "completed_steps": result.completed_steps,
        "remaining_steps": result.remaining_steps,
    }
    if result.step_result:
        response["errors"] = result.step_result.errors

    if result.auth_result:
        response["access_token"] = result.auth_result.access_token
        response["refresh_token"] = result.auth_result.refresh_token

    return JSONResponse(response)


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


app = Starlette(routes=[
    Route("/onboarding/start", start, methods=["POST"]),
    Route("/onboarding/advance", advance, methods=["POST"]),
])
```
