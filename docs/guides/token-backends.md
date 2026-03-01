# Token Backends

tortoise-auth uses a **database-backed token backend** by default and defines a
`TokenBackend` Protocol that lets you plug in your own implementation.

## Database Backend

::: info "Module"
    `tortoise_auth.tokens.database.DatabaseTokenBackend`

The Database backend persists every token in the database and verifies tokens by
looking up their hash. This gives you full control over revocation and token
lifecycle.

### Setup

The Database backend requires two Tortoise ORM models: `AccessToken` and
`RefreshToken`. You must register `tortoise_auth.models` in your Tortoise
configuration so the ORM discovers these tables.

```python
TORTOISE_ORM = {
    "connections": {
        "default": "sqlite://db.sqlite3",
    },
    "apps": {
        "models": {
            "models": ["your_app.models", "aerich.models"],
        },
        "tortoise_auth": {
            "models": ["tortoise_auth.models"],
        },
    },
}
```

This creates two tables:

| Table                             | Model          | Purpose                 |
|-----------------------------------|----------------|-------------------------|
| `tortoise_auth_access_tokens`     | `AccessToken`  | Stores access tokens    |
| `tortoise_auth_refresh_tokens`    | `RefreshToken`  | Stores refresh tokens   |

After registering the models, generate and run migrations with your migration
tool (e.g., Aerich) so the tables are created in the database.

### Token Storage

Tokens are **never stored in plaintext**. When a token is created:

1. A cryptographically secure random string is generated (length controlled by
   `AuthConfig.token_length`, default `64`).
2. The raw string is hashed with **SHA-256** before being written to the
   database.
3. The raw string is returned to the caller in the `TokenPair`.

On verification, the presented token is hashed again with SHA-256 and looked up
in the database. This means that even if the database is compromised, the raw
tokens cannot be recovered.

### Full Revocation Support

The Database backend supports both single-token and bulk revocation:

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend

backend = DatabaseTokenBackend()

# Revoke a single token (tries access table first, then refresh)
await backend.revoke_token(raw_token)

# Revoke ALL tokens for a user
await backend.revoke_all_for_user("42")
```

`revoke_token` sets `is_revoked = True` on the matching row. It first checks
the access token table; if no row matches, it checks the refresh token table.

`revoke_all_for_user` marks every non-revoked access **and** refresh token for
the given `user_id` as revoked in a single pass.

### Cleaning Up Expired Tokens

Over time, expired tokens accumulate in the database. The `cleanup_expired()`
method deletes all tokens whose `expires_at` is in the past and returns the
total number of deleted rows:

```python
backend = DatabaseTokenBackend()
deleted = await backend.cleanup_expired()
print(f"Removed {deleted} expired tokens")
```

You should call this method periodically -- for example, in a scheduled Celery
or APScheduler task:

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend


async def cleanup_tokens_task() -> None:
    """Periodic task to purge expired tokens from the database."""
    backend = DatabaseTokenBackend()
    deleted = await backend.cleanup_expired()
    logger.info("Cleaned up %d expired tokens", deleted)
```

---

## JWT Backend

::: info "Module"
    `tortoise_auth.tokens.jwt.JWTBackend`

The JWT backend issues stateless JSON Web Tokens signed with HMAC-SHA256. Tokens
are verified by checking the signature and expiration — no database lookup is
required. This makes the JWT backend ideal for high-throughput APIs where you
want to avoid a database round-trip on every request.

For revocation, the JWT backend supports an **optional blacklist** backed by two
database tables. When the blacklist is disabled (the default), `revoke_token()`
and `revoke_all_for_user()` are no-ops — this mirrors the approach used by
`djangorestframework-simplejwt`.

### Setup

The JWT backend requires the `PyJWT` library (installed automatically as a
dependency).

```python
from tortoise_auth import AuthConfig, configure
from tortoise_auth.tokens.jwt import JWTBackend

configure(AuthConfig(
    user_model="myapp.User",
    jwt_secret="your-secret-key",  # Required for JWT
))

backend = JWTBackend()
```

If `jwt_secret` is empty, the backend falls back to `signing_secret`.

### Enabling the Blacklist

To enable token revocation, set `jwt_blacklist_enabled=True` and register the
blacklist models with Tortoise ORM:

```python
configure(AuthConfig(
    user_model="myapp.User",
    jwt_secret="your-secret-key",
    jwt_blacklist_enabled=True,
))

TORTOISE_ORM = {
    "connections": {"default": "sqlite://db.sqlite3"},
    "apps": {
        "models": {"models": ["your_app.models"]},
        "tortoise_auth": {
            "models": [
                "tortoise_auth.models",
                "tortoise_auth.models.jwt_blacklist",
            ],
        },
    },
}
```

This creates two tables:

| Table                                | Model              | Purpose                          |
|--------------------------------------|--------------------|----------------------------------|
| `tortoise_auth_outstanding_tokens`   | `OutstandingToken`  | Tracks every JWT issued         |
| `tortoise_auth_blacklisted_tokens`   | `BlacklistedToken`  | Stores revoked token JTIs       |

### Revocation Behavior

| Blacklist | `revoke_token()` | `revoke_all_for_user()` |
|---|---|---|
| Disabled (default) | No-op | No-op |
| Enabled | Adds JTI to `BlacklistedToken` | Blacklists all JTIs from `OutstandingToken` for the user |

### Issuer and Audience

You can set `jwt_issuer` and `jwt_audience` in the config to include `iss` and
`aud` claims in tokens. When set, these claims are verified on token
verification.

```python
configure(AuthConfig(
    jwt_secret="your-secret-key",
    jwt_issuer="myapp",
    jwt_audience="myapi",
))
```

### Cleaning Up Expired Tokens

When the blacklist is enabled, expired outstanding tokens and their blacklist
entries accumulate over time. Call `cleanup_expired()` periodically:

```python
backend = JWTBackend()
deleted = await backend.cleanup_expired()
print(f"Removed {deleted} expired token records")
```

### Using with AuthService

Pass the JWT backend to `AuthService` like any other backend:

```python
from tortoise_auth.services.auth import AuthService
from tortoise_auth.tokens.jwt import JWTBackend

auth = AuthService(backend=JWTBackend())
result = await auth.login("user@example.com", "password123")
# result.access_token is a JWT string
```

---

## The `TokenBackend` Protocol

The built-in backend conforms to the `TokenBackend` Protocol defined in
`tortoise_auth.tokens`. You can write your own backend (for example, backed by
Redis) by implementing this Protocol:

```python
from typing import Any, Protocol, runtime_checkable

from tortoise_auth.tokens import TokenPair, TokenPayload


@runtime_checkable
class TokenBackend(Protocol):
    """Protocol that all token backends must satisfy."""

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair: ...
    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload: ...
    async def revoke_token(self, token: str) -> None: ...
    async def revoke_all_for_user(self, user_id: str) -> None: ...
```

Because this is a `runtime_checkable` Protocol, you can verify at runtime that
your class satisfies the interface:

```python
assert isinstance(MyRedisBackend(), TokenBackend)
```

### Writing a Custom Backend

Here is a skeleton for a Redis-backed token backend:

```python
from typing import Any

from tortoise_auth.tokens import TokenBackend, TokenPair, TokenPayload


class RedisTokenBackend:
    """Example: token backend using Redis for storage and revocation."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        # Generate tokens, store in Redis with TTL matching lifetime
        ...

    async def verify_token(
        self, token: str, *, token_type: str = "access"
    ) -> TokenPayload:
        # Look up token in Redis, check expiration and revocation
        ...

    async def revoke_token(self, token: str) -> None:
        # Delete or mark the token in Redis
        ...

    async def revoke_all_for_user(self, user_id: str) -> None:
        # Delete all tokens for the user from Redis
        ...


# Verify the implementation satisfies the protocol
assert isinstance(RedisTokenBackend("redis://localhost"), TokenBackend)
```

Pass your custom backend to `AuthService`:

```python
from tortoise_auth.services.auth import AuthService

auth = AuthService(backend=RedisTokenBackend("redis://localhost:6379"))
result = await auth.login("user@example.com", "password123")
```

### Methods Reference

| Method               | Parameters                                      | Returns        | Description                                                    |
|----------------------|-------------------------------------------------|----------------|----------------------------------------------------------------|
| `create_tokens`      | `user_id: str`, `**extra: Any`                  | `TokenPair`    | Create an access/refresh token pair for the given user.        |
| `verify_token`       | `token: str`, `token_type: str = "access"`      | `TokenPayload` | Decode and verify a token. Raises on expiration, revocation, or invalidity. |
| `revoke_token`       | `token: str`                                    | `None`         | Revoke a single token so it can no longer be verified.         |
| `revoke_all_for_user`| `user_id: str`                                  | `None`         | Revoke every token belonging to the given user.                |

### Exceptions Raised by Backends

All backends raise exceptions from `tortoise_auth.exceptions`:

| Exception           | When                                           |
|---------------------|-------------------------------------------------|
| `TokenExpiredError` | The token has expired.                          |
| `TokenInvalidError` | The token cannot be decoded, has the wrong type, or is not found in the database. |
| `TokenRevokedError` | The token has been explicitly revoked.          |

All three inherit from `TokenError`, which inherits from `TortoiseAuthError`.

---

## Data Types

Token backends operate on three frozen dataclasses defined in
`tortoise_auth.tokens`.

### `TokenPair`

Returned by `create_tokens()`. Contains the raw token strings that should be
sent to the client.

```python
@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
```

### `AuthResult`

Returned by `AuthService.login()`. Wraps the authenticated user together with
both tokens.

```python
@dataclass(frozen=True, slots=True)
class AuthResult:
    user: Any
    access_token: str
    refresh_token: str

    @property
    def tokens(self) -> TokenPair:
        """Return just the token pair, without the user object."""
        ...
```

The `.tokens` property is convenient when you need to pass only the token
strings to a serializer or response builder:

```python
result = await auth.login("user@example.com", "password123")

# Access individual fields
print(result.user.email)
print(result.access_token)

# Or extract just the token pair
token_pair: TokenPair = result.tokens
```

### `TokenPayload`

Returned by `verify_token()`. A structured representation of the decoded token,
regardless of which backend produced it.

```python
@dataclass(frozen=True, slots=True)
class TokenPayload:
    sub: str                          # User ID as a string
    token_type: str                   # "access" or "refresh"
    jti: str                          # Unique token identifier
    iat: int                          # Issued-at (Unix epoch)
    exp: int                          # Expiration (Unix epoch)
    extra: dict[str, Any] | None = None  # Extra claims (custom backends only)
```

---

## Using the Backend Directly

While `AuthService` is the recommended entry point for authentication workflows,
you can use the backend directly when you need lower-level token operations without
user lookup or event emission.

### Creating and Verifying Tokens

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend

backend = DatabaseTokenBackend()

# Create tokens (persisted in the database)
pair = await backend.create_tokens("42")
print(pair.access_token)
print(pair.refresh_token)

# Verify the access token
payload = await backend.verify_token(pair.access_token, token_type="access")
print(payload.sub)         # "42"
print(payload.token_type)  # "access"

# Verify the refresh token
refresh_payload = await backend.verify_token(
    pair.refresh_token, token_type="refresh"
)
print(refresh_payload.sub)  # "42"
```

### Revoking Tokens

```python
# Revoke a single token
await backend.revoke_token(pair.access_token)

# This now raises TokenRevokedError
await backend.verify_token(pair.access_token)

# Revoke all tokens for a user
await backend.revoke_all_for_user("42")

# Clean up expired tokens
deleted = await backend.cleanup_expired()
```

!!! tip "When to use the backend directly"
    Direct backend usage is appropriate for background jobs, management
    commands, or internal services that need to issue or revoke tokens without
    going through the full login flow. For request-handling code that needs
    user authentication, prefer `AuthService`.
