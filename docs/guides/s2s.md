# Server-to-Server Authentication

tortoise-auth provides a lightweight server-to-server (S2S) authentication
mechanism for internal service communication. Unlike user-based authentication,
S2S auth does not require a user model or database -- it verifies a static
bearer token defined in an environment variable.

---

## When to use S2S authentication

Use `S2SService` when:

- An internal microservice calls your API and there is no user context.
- You need a simple shared-secret authentication without JWT overhead.
- You want token rotation without application restarts.

For user-facing authentication, use [AuthService](authentication.md) instead.

---

## Configuration

Enable S2S authentication in your `AuthConfig`:

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="myapp.User",
    s2s_enabled=True,
    s2s_token_env_var="S2S_AUTH_TOKEN",  # default
))
```

| Field | Type | Default | Description |
|---|---|---|---|
| `s2s_enabled` | `bool` | `False` | Enable S2S authentication. Must be `True` for `S2SService` to work. |
| `s2s_token_env_var` | `str` | `"S2S_AUTH_TOKEN"` | Name of the environment variable containing the valid token(s). |

Then set the environment variable in your deployment:

```bash
export S2S_AUTH_TOKEN="your-secret-service-token"
```

!!! warning
    Never hardcode the token in source code. Always use environment variables,
    a secrets manager, or your deployment platform's secret management.

---

## Basic usage

```python
from tortoise_auth import S2SService

s2s = S2SService()

# Verify a token from an incoming request
result = await s2s.authenticate(token)
# result.service_name is None unless provided
```

The `authenticate()` method:

- Returns an `S2SAuthResult` on success.
- Raises `AuthenticationError` if the token does not match.
- Raises `ConfigurationError` if S2S is not enabled or the env var is missing.

### Passing a service name

You can pass an optional `service_name` for auditing:

```python
result = await s2s.authenticate(token, service_name="billing-service")
print(result.service_name)  # "billing-service"
```

---

## Token rotation

The environment variable supports **comma-separated tokens** for zero-downtime
rotation:

```bash
export S2S_AUTH_TOKEN="new-token,old-token"
```

Both tokens are accepted. To rotate:

1. Add the new token alongside the old one: `new-token,old-token`
2. Deploy all services with the new token as the caller.
3. Remove the old token: `new-token`

Tokens are read from the environment on every call, so rotation takes effect
without restarting the application.

!!! tip
    Whitespace around tokens is automatically stripped, so
    `"token-a , token-b"` works as expected.

---

## Events

`S2SService` emits two events for auditing:

| Event | Keyword arguments | Description |
|---|---|---|
| `s2s_auth_success` | `service_name` | A token was successfully verified. |
| `s2s_auth_failed` | `service_name` | A token verification failed. |

```python
from tortoise_auth import on

@on("s2s_auth_success")
async def log_s2s(*, service_name):
    print(f"S2S auth from {service_name}")

@on("s2s_auth_failed")
async def alert_s2s(*, service_name):
    print(f"S2S auth FAILED from {service_name}")
```

---

## Starlette integration

tortoise-auth ships a ready-made Starlette authentication backend for S2S.

### Setting up the middleware

```python
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from tortoise_auth.integrations.starlette import S2SAuthBackend

app = Starlette(routes=[...])
app.add_middleware(AuthenticationMiddleware, backend=S2SAuthBackend())
```

When a valid Bearer token is present, `request.user` is a `ServiceIdentity`
instance. When the token is missing or invalid, `request.user` is an
`AnonymousUser`.

### ServiceIdentity

The `ServiceIdentity` object represents an authenticated service:

| Property | Type | Description |
|---|---|---|
| `is_authenticated` | `bool` | Always `True`. |
| `is_anonymous` | `bool` | Always `False`. |
| `display_name` | `str` | The service name, or `"service"` if not provided. |
| `service_name` | `str \| None` | The value of the `X-Service-Name` header, if present. |

### Service name header

By default, `S2SAuthBackend` reads the `X-Service-Name` header to identify
the calling service. This is optional and purely for auditing.

```python
# Custom header name
backend = S2SAuthBackend(service_name_header="X-Caller-Service")

# Disable service name extraction
backend = S2SAuthBackend(service_name_header=None)
```

### Custom scopes

The default scopes are `("authenticated", "s2s")`:

```python
backend = S2SAuthBackend(scopes=("internal", "admin"))
```

### Using `require_s2s()`

The `require_s2s()` helper extracts the `ServiceIdentity` from the request
or raises `AuthenticationError`. It also rejects requests authenticated with
a user token (as opposed to an S2S token).

```python
from tortoise_auth.integrations.starlette import require_s2s

async def internal_endpoint(request):
    svc = require_s2s(request)
    return JSONResponse({"caller": svc.display_name})
```

---

## Complete example

```python
import os

from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tortoise_auth import AuthConfig, configure
from tortoise_auth.integrations.starlette import S2SAuthBackend, require_s2s


async def health(request: Request) -> JSONResponse:
    """Public health check."""
    return JSONResponse({"status": "ok"})


async def internal_sync(request: Request) -> JSONResponse:
    """Internal endpoint protected by S2S auth."""
    svc = require_s2s(request)
    return JSONResponse({"caller": svc.display_name, "data": "sensitive"})


app = Starlette(
    routes=[
        Route("/health", health),
        Route("/internal/sync", internal_sync),
    ],
)
app.add_middleware(AuthenticationMiddleware, backend=S2SAuthBackend())


@app.on_event("startup")
async def startup() -> None:
    configure(AuthConfig(
        user_model="myapp.User",
        s2s_enabled=True,
    ))
```

Test it:

```bash
# Set the token
export S2S_AUTH_TOKEN="my-internal-secret"

# Public endpoint -- no auth needed
curl http://localhost:8000/health

# Internal endpoint -- requires S2S token
curl http://localhost:8000/internal/sync \
  -H "Authorization: Bearer my-internal-secret" \
  -H "X-Service-Name: billing-service"
```

---

## Security considerations

- **Constant-time comparison** -- token verification uses `hmac.compare_digest`
  to prevent timing attacks.
- **Tokens are never stored** -- the token lives only in the environment
  variable and is compared in memory. Nothing is written to the database.
- **Environment-only** -- the token value never appears in `AuthConfig`, logs,
  or serialized config. It is read from `os.environ` on each request.

---

## API reference

### `S2SService`

```python
class S2SService:
    def __init__(self, config: AuthConfig | None = None) -> None: ...
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `AuthConfig \| None` | `None` | Optional config. Falls back to global config. |

#### `S2SService.authenticate`

```python
async def authenticate(
    self, token: str, *, service_name: str | None = None
) -> S2SAuthResult
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | *(required)* | The bearer token to verify. |
| `service_name` | `str \| None` | `None` | Optional caller identifier for auditing. |

**Returns:** `S2SAuthResult` on success.

**Raises:**

- `ConfigurationError` -- S2S not enabled or env var not set.
- `AuthenticationError` -- token does not match.

### `S2SAuthResult`

```python
@dataclass(frozen=True, slots=True)
class S2SAuthResult:
    service_name: str | None = None
```

| Field | Type | Description |
|---|---|---|
| `service_name` | `str \| None` | The service name passed to `authenticate()`. |
