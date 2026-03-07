# Use Cases & Cookbook

This page contains complete, copy-pasteable examples for common authentication
scenarios. Each example is self-contained and shows the relevant imports.

---

## User Registration & Login

A complete flow from creating a user to authenticating API calls.

```python
from tortoise_auth import AbstractUser, AuthConfig, AuthService, configure
from tortoise_auth.validators import validate_password
from tortoise_auth.exceptions import InvalidPasswordError


class User(AbstractUser):
    class Meta:
        table = "users"


configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
))


async def register(email: str, password: str) -> User:
    """Register a new user with validated password."""
    # Validate password against all built-in rules
    validate_password(password)

    user = await User.create(email=email)
    await user.set_password(password)
    return user


async def login(email: str, password: str):
    """Login and return tokens."""
    auth = AuthService()
    result = await auth.login(email, password)
    return {
        "user_id": str(result.user.pk),
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
    }
```

---

## Email Verification

Use `make_token` / `verify_token` to generate time-limited, HMAC-signed links
for email confirmation.

```python
from tortoise_auth import make_token, verify_token
from tortoise_auth.exceptions import SignatureExpiredError, BadSignatureError


async def send_verification_email(user):
    """Generate a verification token and send it via email."""
    token = make_token(str(user.pk), secret="your-signing-secret")
    verification_url = f"https://app.example.com/verify?token={token}"
    # send_email(user.email, verification_url)


async def verify_email(token: str):
    """Verify the token from the email link (valid for 24 hours)."""
    try:
        user_id = verify_token(token, max_age=86_400, secret="your-signing-secret")
    except SignatureExpiredError:
        raise ValueError("Verification link has expired. Please request a new one.")
    except BadSignatureError:
        raise ValueError("Invalid verification link.")

    user = await User.get(pk=user_id)
    user.is_verified = True
    await user.save(update_fields=["is_verified"])
    return user
```

---

## Password Reset

Secure password reset flow with a short-lived signed token. After resetting,
invalidate all existing sessions.

```python
from tortoise_auth import AuthService, make_token, verify_token
from tortoise_auth.validators import validate_password


async def request_password_reset(email: str):
    """Generate a reset token (valid for 1 hour)."""
    user = await User.filter(email=email).first()
    if user is None:
        return  # don't reveal whether the email exists

    token = make_token(str(user.pk), secret="your-signing-secret")
    reset_url = f"https://app.example.com/reset?token={token}"
    # send_email(user.email, reset_url)


async def reset_password(token: str, new_password: str):
    """Verify the reset token and set the new password."""
    user_id = verify_token(token, max_age=3600, secret="your-signing-secret")

    validate_password(new_password)

    user = await User.get(pk=user_id)
    await user.set_password(new_password)

    # Invalidate all existing sessions
    auth = AuthService()
    await auth.logout_all(str(user.pk))
```

---

## "Remember Me" / Long-lived Sessions

Configure longer token lifetimes for persistent sessions.

```python
from tortoise_auth import AuthConfig, configure

# Default: 15-minute access, 7-day refresh
configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    access_token_lifetime=900,       # 15 minutes
    refresh_token_lifetime=604_800,  # 7 days
))

# For "remember me": extend the refresh token lifetime
configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    access_token_lifetime=900,         # 15 minutes
    refresh_token_lifetime=2_592_000,  # 30 days
))
```

You can also create separate `AuthService` instances with different configs:

```python
from tortoise_auth import AuthConfig, AuthService

short_session_config = AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    refresh_token_lifetime=604_800,  # 7 days
)

long_session_config = AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    refresh_token_lifetime=2_592_000,  # 30 days
)

# Use the appropriate service based on user preference
auth = AuthService(config=long_session_config if remember_me else short_session_config)
result = await auth.login(email, password)
```

---

## Force Logout Everywhere

After a password change or security incident, revoke all tokens for a user.

```python
from tortoise_auth import AuthService

auth = AuthService()


async def change_password_and_logout(user, new_password: str):
    """Change password and invalidate all sessions."""
    await user.set_password(new_password)
    await auth.logout_all(str(user.pk))
```

---

## Audit Logging

Use the event system to log all authentication activity.

```python
import logging
from tortoise_auth import on

logger = logging.getLogger("auth.audit")


@on("user_login")
async def log_login(user):
    logger.info("LOGIN user=%s email=%s", user.pk, user.email)


@on("user_login_failed")
async def log_failed_login(*, identifier: str, reason: str):
    logger.warning("LOGIN_FAILED identifier=%s reason=%s", identifier, reason)


@on("user_logout")
async def log_logout(user):
    logger.info("LOGOUT user=%s email=%s", user.pk, user.email)


@on("password_changed")
async def log_password_change(user):
    logger.info("PASSWORD_CHANGED user=%s email=%s", user.pk, user.email)
```

---

## Account Lockout on Failed Logins

Use the `user_login_failed` event to implement a simple lockout mechanism.

```python
from collections import defaultdict
from tortoise_auth import on

# In-memory counter (use Redis or DB in production)
failed_attempts: dict[str, int] = defaultdict(int)
MAX_ATTEMPTS = 5


@on("user_login_failed")
async def track_failed_attempts(*, identifier: str, reason: str):
    if reason == "bad_password":
        failed_attempts[identifier] += 1
        if failed_attempts[identifier] >= MAX_ATTEMPTS:
            # Lock the account
            user = await User.filter(email=identifier).first()
            if user:
                user.is_active = False
                await user.save(update_fields=["is_active"])


@on("user_login")
async def reset_failed_attempts(user):
    failed_attempts.pop(user.email, None)
```

---

## Password Change Notification

Send an email notification whenever a user's password changes.

```python
from tortoise_auth import on


@on("password_changed")
async def notify_password_change(user):
    # send_email(
    #     to=user.email,
    #     subject="Your password was changed",
    #     body="If you did not make this change, contact support immediately.",
    # )
    pass
```

---

## Migrating from Django

If you are importing users from a Django project, their password hashes
(PBKDF2-SHA256 or bcrypt) work out of the box. tortoise-auth auto-detects the
hash format and transparently upgrades to Argon2id on the next successful login.

```python
# Import users with their existing Django hashes
await User.create(
    email="django-user@example.com",
    password="pbkdf2_sha256$600000$somesalt$somehash",
)

# The user can log in immediately -- no migration script needed
auth = AuthService()
result = await auth.login("django-user@example.com", "their-old-password")
# After login, user.password is now an Argon2id hash
```

The same applies to bcrypt hashes (`$2b$...`).

---

## Multi-tenant Authentication

Use explicit `AuthConfig` instances for per-tenant configuration.

```python
from tortoise_auth import AuthConfig, AuthService
from tortoise_auth.tokens.database import DatabaseTokenBackend

tenant_configs = {
    "acme": AuthConfig(
        user_model="tenants.AcmeUser",
        signing_secret="acme-secret",
        access_token_lifetime=1800,
    ),
    "globex": AuthConfig(
        user_model="tenants.GlobexUser",
        signing_secret="globex-secret",
        access_token_lifetime=900,
    ),
}


def get_auth_service(tenant: str) -> AuthService:
    config = tenant_configs[tenant]
    return AuthService(config=config, backend=DatabaseTokenBackend(config))
```

---

## Custom Token Backend

Implement the `TokenBackend` Protocol for any storage (e.g., Redis):

```python
from tortoise_auth.tokens import TokenBackend, TokenPair, TokenPayload


class RedisTokenBackend:
    """Skeleton Redis-backed token backend."""

    def __init__(self, redis_client, config=None):
        self.redis = redis_client
        self.config = config

    async def create_tokens(self, user_id: str, **extra) -> TokenPair:
        import secrets
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        # Store in Redis with TTL
        await self.redis.setex(f"token:access:{access}", 900, user_id)
        await self.redis.setex(f"token:refresh:{refresh}", 604_800, user_id)
        return TokenPair(access_token=access, refresh_token=refresh)

    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload:
        user_id = await self.redis.get(f"token:{token_type}:{token}")
        if not user_id:
            from tortoise_auth.exceptions import TokenInvalidError
            raise TokenInvalidError("Token not found or expired")
        return TokenPayload(
            sub=user_id, token_type=token_type, jti=token,
            iat=0, exp=0,
        )

    async def revoke_token(self, token: str) -> None:
        await self.redis.delete(f"token:access:{token}")
        await self.redis.delete(f"token:refresh:{token}")

    async def revoke_all_for_user(self, user_id: str) -> None:
        # Scan and delete all tokens for this user
        ...
```

---

## Custom Password Validator

Enforce custom password requirements by implementing the `PasswordValidator`
Protocol.

```python
import re
from tortoise_auth.validators import validate_password, MinimumLengthValidator


class SpecialCharacterValidator:
    """Require at least one special character."""

    def validate(self, password: str, user=None) -> None:
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValueError("Password must contain at least one special character.")

    def get_help_text(self) -> str:
        return "Your password must contain at least one special character."


class UppercaseValidator:
    """Require at least one uppercase letter."""

    def validate(self, password: str, user=None) -> None:
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter.")

    def get_help_text(self) -> str:
        return "Your password must contain at least one uppercase letter."


# Use in validation
validate_password("MyP@ssword1", validators=[
    MinimumLengthValidator(min_length=10),
    SpecialCharacterValidator(),
    UppercaseValidator(),
])
```

You can also set custom validators as the default via `AuthConfig`:

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    password_validators=[
        MinimumLengthValidator(min_length=12),
        SpecialCharacterValidator(),
        UppercaseValidator(),
    ],
))
```

---

## OAuth / Social Login Users

For users who authenticate via OAuth providers (Google, GitHub, etc.), mark
their password as unusable:

```python
async def create_oauth_user(email: str, provider: str) -> User:
    user = await User.create(email=email)
    user.set_unusable_password()
    await user.save()
    return user


async def check_login_method(user):
    if not user.has_usable_password():
        # Redirect to OAuth provider instead of showing password form
        ...
```

---

## Invite Links

Generate time-limited signed invite URLs.

```python
from tortoise_auth import make_token, verify_token


def create_invite_link(inviter_id: str, team_id: str) -> str:
    """Create an invite link valid for 72 hours."""
    payload = f"{inviter_id}:{team_id}"
    token = make_token(payload, secret="your-signing-secret")
    return f"https://app.example.com/invite?token={token}"


async def accept_invite(token: str, user):
    """Accept an invite (valid for 72 hours)."""
    payload = verify_token(token, max_age=259_200, secret="your-signing-secret")
    inviter_id, team_id = payload.split(":")
    # Add user to the team...
```

---

## Unsubscribe Links

Use `Signer` (without timestamp) for permanent links that never expire.

```python
from tortoise_auth import Signer


signer = Signer(secret="your-signing-secret")


def create_unsubscribe_link(user_id: str) -> str:
    """Create a permanent unsubscribe link."""
    signed = signer.sign(user_id)
    return f"https://app.example.com/unsubscribe?token={signed}"


async def unsubscribe(token: str):
    """Verify and process unsubscribe."""
    user_id = signer.unsign(token)  # raises BadSignatureError if tampered
    user = await User.get(pk=user_id)
    # Unsubscribe the user...
```

---

## Starlette Full REST API

A complete Starlette application with registration, login, token refresh,
profile, and logout endpoints.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tortoise_auth import (
    AbstractUser,
    AuthConfig,
    AuthService,
    configure,
)
from tortoise_auth.exceptions import AuthenticationError, InvalidPasswordError
from tortoise_auth.integrations.starlette import (
    TokenAuthBackend,
    login_required,
    require_auth,
)
from tortoise_auth.validators import validate_password


class User(AbstractUser):
    class Meta:
        table = "users"


configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
))

auth = AuthService()


async def register(request: Request) -> JSONResponse:
    body = await request.json()
    email, password = body["email"], body["password"]

    try:
        validate_password(password)
    except InvalidPasswordError as exc:
        return JSONResponse({"errors": exc.errors}, status_code=400)

    user = await User.create(email=email)
    await user.set_password(password)

    result = await auth.login(email, password)
    return JSONResponse({
        "user_id": str(user.pk),
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
    }, status_code=201)


async def login(request: Request) -> JSONResponse:
    body = await request.json()
    try:
        result = await auth.login(body["email"], body["password"])
    except AuthenticationError:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    return JSONResponse({
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
    })


async def refresh(request: Request) -> JSONResponse:
    body = await request.json()
    tokens = await auth.refresh(body["refresh_token"])
    return JSONResponse({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
    })


@login_required
async def me(request: Request) -> JSONResponse:
    user = require_auth(request)
    return JSONResponse({
        "id": str(user.pk),
        "email": user.email,
        "is_verified": user.is_verified,
    })


@login_required
async def logout(request: Request) -> JSONResponse:
    token = request.headers["Authorization"].removeprefix("Bearer ")
    await auth.logout(token)
    return JSONResponse({"detail": "Logged out"})


app = Starlette(
    routes=[
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/refresh", refresh, methods=["POST"]),
        Route("/me", me),
        Route("/logout", logout, methods=["POST"]),
    ],
    middleware=[
        Middleware(AuthenticationMiddleware, backend=TokenAuthBackend()),
    ],
)
```

---

## Choosing Between JWT and Database Tokens

| Aspect | JWT (`JWTBackend`) | Database (`DatabaseTokenBackend`) |
|--------|--------------------|----------------------------------|
| **Storage** | Stateless (token contains all data) | Server-side (opaque tokens in DB) |
| **Revocation** | Requires blacklist (`jwt_blacklist_enabled=True`) | Instant, built-in |
| **Scalability** | No DB lookup on authenticate | DB lookup on every request |
| **Token size** | Larger (~300+ bytes) | Smaller (~64 bytes) |
| **Best for** | Microservices, API gateways | Monoliths, session management |

### Using Database Tokens

```python
from tortoise_auth import AuthConfig, AuthService, configure
from tortoise_auth.tokens.database import DatabaseTokenBackend

configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
))

auth = AuthService(backend=DatabaseTokenBackend())
```

!!! note
    The database backend requires the `AccessToken` and `RefreshToken` models
    to be registered with Tortoise ORM. Add `"tortoise_auth.models"` to your
    Tortoise config's `apps` modules.

### Using JWT Tokens

```python
from tortoise_auth import AuthConfig, AuthService, configure

configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="your-secret-key",
    jwt_secret="your-jwt-secret",        # falls back to signing_secret if empty
    jwt_blacklist_enabled=True,           # enable revocation support
))

auth = AuthService()  # defaults to JWTBackend
```

---

## Periodic Token Cleanup

Expired database tokens and JWT blacklist entries accumulate over time. Schedule
a periodic cleanup task to purge them.

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend


async def cleanup_expired_tokens():
    """Run periodically (e.g., daily via cron or APScheduler)."""
    backend = DatabaseTokenBackend()
    deleted = await backend.cleanup_expired()
    print(f"Cleaned up {deleted} expired tokens")
```

With APScheduler:

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()
scheduler.add_job(cleanup_expired_tokens, "interval", hours=24)
scheduler.start()
```

With a simple background task (Starlette lifespan):

```python
import asyncio
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(token_cleanup_loop())
    yield
    task.cancel()


async def token_cleanup_loop():
    backend = DatabaseTokenBackend()
    while True:
        await asyncio.sleep(86_400)  # every 24 hours
        await backend.cleanup_expired()
```
