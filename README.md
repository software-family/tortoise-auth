# tortoise-auth

![Development Status](https://img.shields.io/badge/status-alpha-orange)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Async authentication and user management for Tortoise ORM.**
Framework-agnostic, extensible, secure by default.

**tortoise-auth** is a pure-async authentication library built on top of
[Tortoise ORM](https://tortoise.github.io/). It provides a complete user
authentication stack — password hashing, token issuance, session management,
HMAC signing, and lifecycle events — without coupling you to any particular web
framework. Define your user model, call `configure()`, and you have a
production-ready auth layer that works with FastAPI, Starlette, Sanic, or any
other async Python framework.

> [!WARNING]
> **This project is under active development (v0.2.0, Alpha).** The public API
> may change between releases. Use in production at your own risk.

## Features

- **Abstract User model** — extend `AbstractUser` to get email-based
  authentication, password hashing, `is_active` / `is_verified` flags, and
  timestamp tracking out of the box.
- **AuthService** — high-level async API for `login`, `authenticate`,
  `refresh`, `logout`, and `logout_all`.
- **Pluggable token backends** — choose between stateless **JWT** tokens or
  server-side **database** tokens, swappable with a single config flag.
- **Multi-algorithm password hashing** — Argon2id (primary), Bcrypt, and
  PBKDF2-SHA256 with transparent auto-migration to the strongest hasher.
- **Password validation** — four built-in validators (minimum length, common
  password list, numeric-only, user-attribute similarity) plus custom validators
  via the `PasswordValidator` Protocol.
- **HMAC signing** — `Signer`, `TimestampSigner`, and convenience helpers
  `make_token` / `verify_token` for email-confirmation links, password-reset
  URLs, and other signed payloads.
- **Event system** — subscribe to `user_login`, `user_login_failed`,
  `user_logout`, and `password_changed` events with async handlers.
- **Fully async** — every I/O operation uses `await`; no hidden synchronous
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
    """Application user model."""

    class Meta:
        table = "users"


# Configure the library
configure(AuthConfig(
    user_model="models.User",
    jwt_secret="your-secret-key",
))


# Usage (inside an async context)
auth = AuthService()
result = await auth.login("user@example.com", "password123")
user = await auth.authenticate(result.access_token)
```

> [!CAUTION]
> The snippet above uses a literal `jwt_secret` for brevity. In production,
> always load secrets from environment variables or a dedicated secrets manager.

## Requirements

- Python 3.12+
- Tortoise ORM 0.21+

## License

MIT — see [LICENSE](LICENSE) for details.
