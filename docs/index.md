# tortoise-auth

**Async authentication and user management for Tortoise ORM.**
Framework-agnostic, extensible, secure by default.

---

**tortoise-auth** is a pure-async authentication library built on top of
[Tortoise ORM](https://tortoise.github.io/). It provides a complete user
authentication stack -- password hashing, token issuance, session management,
HMAC signing, and lifecycle events -- without coupling you to any particular web
framework. Define your user model, call `configure()`, and you have a
production-ready auth layer that works with FastAPI, Starlette, Sanic, or any
other async Python framework.

## What You Can Build

tortoise-auth covers the most common authentication scenarios out of the box:

| Use Case | Features Used |
|----------|--------------|
| **User registration & login** | `AbstractUser`, `AuthService.login` |
| **Multi-step onboarding** | `OnboardingService` — server-driven register → verify → TOTP flow |
| **Protected API endpoints** | `AuthService.authenticate`, Starlette `TokenAuthBackend` |
| **Server-to-server auth** | `S2SService`, Starlette `S2SAuthBackend` |
| **Token refresh rotation** | `AuthService.refresh` |
| **Email verification** | `make_token` / `verify_token` (HMAC signing) |
| **Password reset** | `make_token` / `verify_token` with `max_age` |
| **Invite links & unsubscribe URLs** | `Signer` / `TimestampSigner` |
| **Force logout everywhere** | `AuthService.logout_all` |
| **Audit logging & notifications** | Event system (`on`, `emit`) |
| **Account lockout on failed logins** | `user_login_failed` event |
| **Migrating password hashes from Django** | Auto-migration (Argon2id, bcrypt, PBKDF2) |
| **OAuth / social login users** | `set_unusable_password()` |

See the [Use Cases & Cookbook](guides/use-cases.md) for complete, copy-pasteable examples.

## Key Features

- **Abstract User model** -- extend `AbstractUser` to get email-based
  authentication, password hashing, `is_active` / `is_verified` flags, and
  timestamp tracking out of the box.
- **AuthService** -- high-level async API for `login`, `authenticate`,
  `refresh`, `logout`, and `logout_all`.
- **Pluggable token backends** -- choose between stateless **JWT** tokens or
  server-side **database** tokens. Both implement the `TokenBackend` Protocol
  for easy swapping or custom backends.
- **Multi-algorithm password hashing** -- Argon2id (primary), Bcrypt, and
  PBKDF2-SHA256 with transparent auto-migration to the strongest hasher.
- **Password validation** -- four built-in validators (minimum length, common
  password list, numeric-only, user-attribute similarity) plus custom validators
  via the `PasswordValidator` Protocol.
- **HMAC signing** -- `Signer`, `TimestampSigner`, and convenience helpers
  `make_token` / `verify_token` for email-confirmation links, password-reset
  URLs, and other signed payloads.
- **Onboarding flow engine** -- server-driven, multi-step onboarding with
  built-in steps for registration, email verification, TOTP setup, and profile
  completion. Pluggable via the `OnboardingStep` Protocol.
- **Event system** -- subscribe to `user_login`, `user_login_failed`,
  `user_logout`, and `password_changed` events with async handlers.
- **Server-to-server authentication** -- `S2SService` for service-to-service
  communication using env-var-based tokens with constant-time comparison.
- **Starlette integration** -- `TokenAuthBackend`, `S2SAuthBackend`,
  `login_required` decorator, and `require_auth` / `require_s2s` helpers for
  Starlette and FastAPI apps.
- **Fully async** -- every I/O operation uses `await`; no hidden synchronous
  calls.

## Quick Example

```python
from tortoise_auth import AbstractUser, AuthConfig, AuthService, configure


class User(AbstractUser):
    """Application user model."""

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

!!! warning "Do not hardcode secrets"
    The snippet above uses a literal `signing_secret` for brevity. In production,
    always load secrets from environment variables or a dedicated secrets
    manager.

## Installation

```bash
pip install tortoise-auth
```

!!! note "Optional dependencies"
    Argon2 hashing requires the `argon2-cffi` package, which is installed
    automatically as a dependency of tortoise-auth.

## Quick Navigation

<div class="grid" markdown>

- :material-rocket-launch: **[Quick Start](getting-started/quickstart.md)** -- Set up your first project in under five minutes
- :material-cog: **[Configuration](guides/configuration.md)** -- All configuration options explained
- :material-key: **[Authentication](guides/authentication.md)** -- Login, logout, and token management
- :material-database: **[Token Backends](guides/token-backends.md)** -- JWT vs database tokens
- :material-lock: **[Password Hashing](guides/password-hashing.md)** -- Argon2id, bcrypt, PBKDF2, and auto-migration
- :material-shield-check: **[Password Validation](guides/password-validation.md)** -- Built-in and custom validators
- :material-signature: **[Signing (HMAC)](guides/signing.md)** -- Signed tokens for email verification and resets
- :material-account-plus: **[Onboarding Flow](guides/onboarding.md)** -- Server-driven multi-step registration
- :material-bell: **[Events](guides/events.md)** -- React to login, logout, and password changes
- :material-server-network: **[S2S Authentication](guides/s2s.md)** -- Service-to-service auth with env-var tokens
- :material-language-python: **[Starlette Integration](integrations/starlette.md)** -- Middleware, decorators, and protected routes
- :material-book-open: **[Use Cases & Cookbook](guides/use-cases.md)** -- Real-world examples you can copy-paste

</div>

## Next Steps

Ready to build? Head over to the [Quick Start](getting-started/quickstart.md)
guide to set up your first project with tortoise-auth in under five minutes.

---

<small>Version 0.4.0</small>
