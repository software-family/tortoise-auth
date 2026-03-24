# tortoise-auth

![Development Status](https://img.shields.io/badge/status-alpha-orange)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Async authentication and user management for Tortoise ORM.**
Framework-agnostic, extensible, secure by default.

**tortoise-auth** is a pure-async authentication library built on top of
[Tortoise ORM](https://tortoise.github.io/). It provides a complete user
authentication stack -- password hashing, token issuance, session management,
HMAC signing, and lifecycle events -- without coupling you to any particular web
framework. Define your user model, call `configure()`, and you have a
production-ready auth layer that works with FastAPI, Starlette, Sanic, or any
other async Python framework.

> [!WARNING]
> **This project is under active development (v0.4.0, Alpha).** The public API
> may change between releases. Use in production at your own risk.

**[Documentation](https://tortoise-auth.softwarefamily.fr/)** |
**[API Reference](https://tortoise-auth.softwarefamily.fr/reference/api/)** |
**[GitHub](https://github.com/software-family/tortoise-auth)**

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Use Cases](#use-cases)
  - [Login and Logout](#login-and-logout)
  - [Token Refresh Rotation](#token-refresh-rotation)
  - [Starlette / FastAPI Integration](#starlette--fastapi-integration)
  - [Server-to-Server Authentication](#server-to-server-authentication)
  - [Email Verification](#email-verification)
  - [Password Reset](#password-reset)
  - [Password Validation](#password-validation)
  - [Event System (Audit Logging)](#event-system-audit-logging)
  - [Database Tokens vs JWT](#database-tokens-vs-jwt)
  - [Hash Migration from Django / bcrypt](#hash-migration-from-django--bcrypt)
  - [Custom User Model](#custom-user-model)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Abstract User model** -- extend `AbstractUser` to get email-based
  authentication, password hashing, `is_active` / `is_verified` flags, and
  timestamp tracking out of the box.
- **AuthService** -- high-level async API for `login`, `authenticate`,
  `refresh`, `logout`, and `logout_all`.
- **Pluggable token backends** -- choose between stateless **JWT** tokens or
  server-side **database** tokens, swappable with a single config flag.
- **Multi-algorithm password hashing** -- Argon2id (primary), Bcrypt, and
  PBKDF2-SHA256 with transparent auto-migration to the strongest hasher.
- **Password validation** -- four built-in validators (minimum length, common
  password list, numeric-only, user-attribute similarity) plus custom validators
  via the `PasswordValidator` Protocol.
- **HMAC signing** -- `Signer`, `TimestampSigner`, and convenience helpers
  `make_token` / `verify_token` for email-confirmation links, password-reset
  URLs, and other signed payloads.
- **Event system** -- subscribe to `user_login`, `user_login_failed`,
  `user_logout`, and `password_changed` events with async handlers.
- **Server-to-server authentication** -- `S2SService` for service-to-service
  communication using static bearer tokens from environment variables, with
  constant-time comparison and token rotation support.
- **Starlette integration** -- `TokenAuthBackend`, `S2SAuthBackend`,
  `login_required` decorator, and `require_auth` / `require_s2s` helpers for
  Starlette and FastAPI apps.
- **Fully async** -- every I/O operation uses `await`; no hidden synchronous
  calls.

## Installation

```bash
pip install tortoise-auth
```

or with [uv](https://docs.astral.sh/uv/):

```bash
uv add tortoise-auth
```

## Quick Start

```python
from tortoise_auth import AbstractUser, AuthConfig, AuthService, configure


class User(AbstractUser):
    class Meta:
        table = "users"


# Configure the library
configure(AuthConfig(
    user_model="models.User",
    signing_secret="your-secret-key",
))

# Usage (inside an async context)
auth = AuthService()
result = await auth.login("user@example.com", "password123")
user = await auth.authenticate(result.access_token)
```

> [!CAUTION]
> The snippet above uses a literal `signing_secret` for brevity. In production,
> always load secrets from environment variables or a dedicated secrets manager.

---

## Use Cases

### Login and Logout

```python
auth = AuthService()

# Login -- returns user + access/refresh tokens
result = await auth.login("user@example.com", "password123")
print(result.access_token)
print(result.refresh_token)

# Authenticate a request
user = await auth.authenticate(result.access_token)

# Logout (revoke a single token)
await auth.logout(result.access_token)

# Force logout everywhere (e.g. after password change)
await auth.logout_all(str(user.pk))
```

### Token Refresh Rotation

Refresh tokens are single-use. Each call to `refresh()` revokes the old token
and issues a new pair:

```python
auth = AuthService()
result = await auth.login("user@example.com", "password123")

# Later, when the access token expires:
new_tokens = await auth.refresh(result.refresh_token)
print(new_tokens.access_token)   # new access token
print(new_tokens.refresh_token)  # new refresh token (old one is revoked)
```

### Starlette / FastAPI Integration

tortoise-auth ships with a ready-made Starlette authentication backend:

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tortoise_auth import AuthService
from tortoise_auth.integrations.starlette import (
    TokenAuthBackend,
    login_required,
    require_auth,
)

auth = AuthService()


async def login(request: Request) -> JSONResponse:
    body = await request.json()
    result = await auth.login(body["email"], body["password"])
    return JSONResponse({
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
    })


@login_required
async def me(request: Request) -> JSONResponse:
    user = require_auth(request)
    return JSONResponse({"email": user.email})


app = Starlette(
    routes=[
        Route("/login", login, methods=["POST"]),
        Route("/me", me),
    ],
    middleware=[
        Middleware(AuthenticationMiddleware, backend=TokenAuthBackend()),
    ],
)
```

### Server-to-Server Authentication

For internal microservice communication where no user is involved, use
`S2SService` with a shared token stored in an environment variable:

```python
import os
from tortoise_auth import AuthConfig, S2SService, configure

# Configure with S2S enabled
configure(AuthConfig(
    user_model="models.User",
    s2s_enabled=True,
    s2s_token_env_var="S2S_AUTH_TOKEN",  # default
))

# Set the token in the environment (or via your deployment config)
# export S2S_AUTH_TOKEN="my-secret-service-token"

# Verify an incoming service request
s2s = S2SService()
result = await s2s.authenticate(token_from_request)
```

Multiple comma-separated tokens are supported for rotation:

```bash
export S2S_AUTH_TOKEN="new-token,old-token"
```

With Starlette, use the `S2SAuthBackend` middleware:

```python
from tortoise_auth.integrations.starlette import S2SAuthBackend, require_s2s

app.add_middleware(AuthenticationMiddleware, backend=S2SAuthBackend())

@login_required
async def internal_endpoint(request):
    svc = require_s2s(request)  # returns ServiceIdentity
    return JSONResponse({"caller": svc.display_name})
```

### Email Verification

Use HMAC-signed tokens for email confirmation links:

```python
from tortoise_auth import make_token, verify_token

# Generate a signed token embedding the user ID
token = make_token(str(user.pk), secret="your-signing-secret")
# Send email with link: https://app.example.com/verify?token=...

# When the user clicks the link:
try:
    user_id = verify_token(token, max_age=86400, secret="your-signing-secret")
    user = await User.get(pk=user_id)
    user.is_verified = True
    await user.save(update_fields=["is_verified"])
except Exception:
    # Token expired or tampered
    ...
```

### Password Reset

Similar to email verification, but with a shorter lifetime:

```python
from tortoise_auth import make_token, verify_token

# 1. User requests a password reset
user = await User.get(email="user@example.com")
token = make_token(str(user.pk), secret="your-signing-secret")
# Send email with link: https://app.example.com/reset?token=...

# 2. User submits a new password with the token
user_id = verify_token(token, max_age=3600, secret="your-signing-secret")
user = await User.get(pk=user_id)
await user.set_password("new-secure-password")

# 3. Invalidate all existing sessions after password change
auth = AuthService()
await auth.logout_all(str(user.pk))
```

### Password Validation

Use the built-in validators or write your own:

```python
from tortoise_auth.validators import (
    validate_password,
    MinimumLengthValidator,
    CommonPasswordValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
)
from tortoise_auth.exceptions import InvalidPasswordError

# Validate with defaults (all four built-in validators)
try:
    validate_password("short")
except InvalidPasswordError as exc:
    print(exc.errors)  # list of validation error messages

# Custom validator
class SpecialCharacterValidator:
    def validate(self, password: str, user=None) -> None:
        if not any(c in password for c in "!@#$%^&*"):
            raise ValueError("Password must contain a special character.")

    def get_help_text(self) -> str:
        return "Your password must contain at least one special character."

# Use custom validators alongside built-ins
validate_password("password123!", validators=[
    MinimumLengthValidator(min_length=10),
    SpecialCharacterValidator(),
])
```

### Event System (Audit Logging)

Subscribe to authentication events for audit logs, notifications, or lockout
logic:

```python
from tortoise_auth import on

@on("user_login")
async def audit_login(user):
    print(f"User {user.email} logged in")

@on("user_login_failed")
async def audit_failed(*, identifier: str, reason: str):
    print(f"Failed login for {identifier}: {reason}")
    # reason is one of: "not_found", "inactive", "bad_password"

@on("user_logout")
async def audit_logout(user):
    print(f"User {user.email} logged out")

@on("password_changed")
async def notify_password_change(user):
    print(f"Password changed for {user.email}")
    # Send notification email...
```

### Database Tokens vs JWT

tortoise-auth supports two token backends. Choose the one that fits your
architecture:

```python
from tortoise_auth import AuthConfig, AuthService, configure
from tortoise_auth.tokens.database import DatabaseTokenBackend
from tortoise_auth.tokens.jwt import JWTBackend

# Option 1: Database tokens (server-side, full revocation)
configure(AuthConfig(
    user_model="models.User",
    signing_secret="your-secret-key",
))
auth = AuthService(backend=DatabaseTokenBackend())

# Option 2: JWT tokens (stateless, default backend)
configure(AuthConfig(
    user_model="models.User",
    signing_secret="your-secret-key",
    jwt_secret="your-jwt-secret",  # optional, falls back to signing_secret
))
auth = AuthService()  # defaults to JWTBackend
```

**When to use database tokens:** you need instant revocation, session listing,
or token audit trails.

**When to use JWT:** you want stateless, horizontally scalable auth with no
database lookups on every request.

### Hash Migration from Django / bcrypt

tortoise-auth auto-migrates password hashes. If you import users from Django or
another system using bcrypt or PBKDF2, passwords are transparently rehashed to
Argon2id on next successful login -- no migration script needed.

```python
# Import a user with a Django PBKDF2 hash
user = await User.create(
    email="migrated@example.com",
    password="pbkdf2_sha256$600000$salt$hash...",  # existing Django hash
)

# On next login, the hash is auto-upgraded to Argon2id
auth = AuthService()
result = await auth.login("migrated@example.com", "their-password")
# user.password is now an Argon2id hash
```

### Custom User Model

Extend `AbstractUser` with any additional fields your application needs:

```python
from tortoise import fields
from tortoise_auth import AbstractUser


class User(AbstractUser):
    username = fields.CharField(max_length=50, unique=True)
    display_name = fields.CharField(max_length=100, default="")
    avatar_url = fields.CharField(max_length=500, default="")

    class Meta:
        table = "users"
```

For OAuth / social login users who authenticate externally:

```python
user = await User.create(email="oauth@example.com")
user.set_unusable_password()  # marks password as unusable
await user.save()

user.has_usable_password()  # False
```

---

## Documentation

Full documentation is available at
**[tortoise-auth.softwarefamily.fr](https://tortoise-auth.softwarefamily.fr/)**.

- [Installation](https://tortoise-auth.softwarefamily.fr/getting-started/installation/)
- [Quick Start](https://tortoise-auth.softwarefamily.fr/getting-started/quickstart/)
- [Configuration](https://tortoise-auth.softwarefamily.fr/guides/configuration/)
- [Token Backends](https://tortoise-auth.softwarefamily.fr/guides/token-backends/)
- [Signing (HMAC)](https://tortoise-auth.softwarefamily.fr/guides/signing/)
- [Events](https://tortoise-auth.softwarefamily.fr/guides/events/)
- [Starlette Integration](https://tortoise-auth.softwarefamily.fr/integrations/starlette/)
- [API Reference](https://tortoise-auth.softwarefamily.fr/reference/api/)

## Requirements

- Python 3.12+
- Tortoise ORM 1.0+

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on
[GitHub](https://github.com/software-family/tortoise-auth).

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes
4. Push to your fork and open a pull request

## License

MIT -- see [LICENSE](LICENSE) for details.
