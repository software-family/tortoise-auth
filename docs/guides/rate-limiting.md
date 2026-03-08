# Rate Limiting

tortoise-auth provides login rate limiting to protect against brute-force attacks. Rate limiting is **opt-in** — it only activates when you pass a `rate_limiter` to `AuthService`.

## Quick Start

```python
from tortoise_auth import AuthConfig, AuthService, InMemoryRateLimitBackend

config = AuthConfig(
    user_model="myapp.User",
    jwt_secret="your-secret-key",
    rate_limit_max_attempts=5,
    rate_limit_window=300,      # 5 minutes
    rate_limit_lockout=600,     # 10 minutes
)

rate_limiter = InMemoryRateLimitBackend(config)
auth = AuthService(config, rate_limiter=rate_limiter)

# Login is now rate-limited per identifier
result = await auth.login("user@example.com", "password")
```

## How It Works

When a `rate_limiter` is configured:

1. **Before** credential verification: check if the identifier is rate-limited. If blocked, raise `RateLimitError` immediately (credentials are never checked).
2. **On any failure** (unknown user, inactive user, wrong password): record a failed attempt. All failure types count equally to prevent user enumeration via rate limit behavior.
3. **On success**: reset the counter for that identifier.

When no `rate_limiter` is configured, the login flow is identical to before — zero overhead.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `rate_limit_max_attempts` | `5` | Maximum failed attempts before lockout |
| `rate_limit_window` | `300` | Window size in seconds (5 minutes) |
| `rate_limit_lockout` | `600` | Lockout duration in seconds (10 minutes) |

## Backends

### In-Memory Backend

Stores attempts in a Python dictionary. Fast and simple, but state is lost on restart and not shared across processes.

```python
from tortoise_auth import InMemoryRateLimitBackend

rate_limiter = InMemoryRateLimitBackend(config)
```

Best for: single-process applications, development, testing.

### Database Backend

Persists attempts in the `tortoise_auth_login_attempts` table via Tortoise ORM. State survives restarts and is shared across processes.

```python
from tortoise_auth import DatabaseRateLimitBackend

rate_limiter = DatabaseRateLimitBackend(config)
```

Register the model module in your Tortoise config:

```python
TORTOISE_ORM = {
    "apps": {
        "tortoise_auth": {
            "models": [
                "tortoise_auth.models.rate_limit",
                # ... other model modules
            ],
        },
    },
}
```

Best for: multi-process deployments, production environments.

## Custom Backends

Implement the `RateLimitBackend` protocol:

```python
from tortoise_auth.rate_limit import RateLimitBackend, RateLimitResult

class RedisRateLimitBackend:
    async def check(self, key: str) -> RateLimitResult:
        # Check if key is rate-limited
        ...

    async def record(self, key: str) -> None:
        # Record a failed attempt
        ...

    async def reset(self, key: str) -> None:
        # Clear attempts on successful login
        ...

    async def cleanup_expired(self) -> int:
        # Purge old records, return count removed
        ...
```

## Handling RateLimitError

`RateLimitError` does **not** inherit from `AuthenticationError`, so you can differentiate between rate limiting (429) and authentication failure (401):

```python
from tortoise_auth import RateLimitError, AuthenticationError

try:
    result = await auth.login(email, password)
except RateLimitError as e:
    # 429 Too Many Requests
    print(f"Try again in {e.retry_after} seconds")
except AuthenticationError:
    # 401 Unauthorized
    print("Invalid credentials")
```

## Starlette Middleware

For IP-based rate limiting on specific HTTP paths:

```python
from tortoise_auth.integrations.starlette import RateLimitMiddleware
from tortoise_auth import InMemoryRateLimitBackend, AuthConfig

config = AuthConfig(rate_limit_max_attempts=10, rate_limit_window=60)
rate_limiter = InMemoryRateLimitBackend(config)

app.add_middleware(
    RateLimitMiddleware,
    rate_limiter=rate_limiter,
    paths=["/api/login", "/api/token"],
)
```

When rate-limited, the middleware returns a `429` JSON response with a `Retry-After` header.

## Cleanup

Both backends support cleaning up expired records:

```python
deleted = await rate_limiter.cleanup_expired()
```

For the database backend, consider running this periodically (e.g., via a cron job or background task) to keep the table small.

## Events

A `rate_limit_exceeded` event is emitted when a login attempt is blocked:

```python
from tortoise_auth import on

@on("rate_limit_exceeded")
async def handle_rate_limit(*, identifier: str, retry_after: int) -> None:
    print(f"Rate limited: {identifier}, retry after {retry_after}s")
```
