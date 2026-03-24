# Starlette

`tortoise-auth` ships a first-class integration for
[Starlette](https://www.starlette.io/) that plugs directly into Starlette's
`AuthenticationMiddleware`. Once configured, every incoming request automatically
carries the authenticated user on `request.user` -- no manual token parsing
required.

The integration provides:

- **`TokenAuthBackend`** -- a Bearer-token authentication backend for user
  tokens.
- **`S2SAuthBackend`** -- a Bearer-token authentication backend for
  server-to-server tokens.
- **`login_required`** -- a decorator to reject unauthenticated requests.
- **`require_auth()`** -- a helper to extract the authenticated user or raise.
- **`require_s2s()`** -- a helper to extract the authenticated service or raise.
- **`AnonymousUser`** -- a placeholder object for unauthenticated requests.
- **`ServiceIdentity`** -- a placeholder object for S2S-authenticated requests.

---

## Installation

Starlette is an optional dependency. Install it alongside `tortoise-auth`:

=== "pip"

    ```bash
    pip install tortoise-auth starlette
    ```

=== "uv"

    ```bash
    uv add tortoise-auth starlette
    ```

You will also need an ASGI server to run your application:

```bash
pip install uvicorn
```

---

## Setting up the middleware

Add `AuthenticationMiddleware` with `TokenAuthBackend` to your Starlette
application. The backend extracts the Bearer token from the `Authorization`
header, verifies it through `AuthService`, and populates `request.user`.

```python
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from tortoise_auth.integrations.starlette import TokenAuthBackend

app = Starlette(routes=[...])
app.add_middleware(AuthenticationMiddleware, backend=TokenAuthBackend())
```

When a valid Bearer token is present, `request.user` is the authenticated user
model instance. When the token is missing, malformed, or invalid,
`request.user` is an `AnonymousUser` -- the middleware **never** returns an
error response by itself.

!!! note
    `TokenAuthBackend` lazily creates an `AuthService` instance on the first
    request. If you use the global `configure()` pattern, there is nothing else
    to configure. If you need to pass a specific `AuthService` (e.g. in tests),
    use the `auth_service` parameter:

    ```python
    svc = AuthService(config=my_config)
    backend = TokenAuthBackend(auth_service=svc)
    ```

---

## Accessing the authenticated user

After the middleware runs, every route handler can inspect `request.user` and
`request.auth`:

```python
from starlette.requests import Request
from starlette.responses import JSONResponse

async def profile(request: Request) -> JSONResponse:
    if request.user.is_authenticated:
        return JSONResponse({
            "email": request.user.email,
            "scopes": list(request.auth.scopes),
        })
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)
```

| Attribute                     | Authenticated          | Anonymous         |
|-------------------------------|------------------------|-------------------|
| `request.user.is_authenticated` | `True`               | `False`           |
| `request.user.is_anonymous`     | `False`              | `True`            |
| `request.user.email`            | user's email         | _(not available)_ |
| `request.auth.scopes`           | `("authenticated",)` | `()`              |

---

## Protecting routes with `login_required`

The `login_required` decorator rejects unauthenticated requests before your
handler runs. It works with and without parentheses.

### Basic usage

```python
from tortoise_auth.integrations.starlette import login_required

@login_required
async def dashboard(request: Request) -> JSONResponse:
    return JSONResponse({"email": request.user.email})
```

Unauthenticated requests receive a `401` JSON response:

```json
{"detail": "Authentication required"}
```

### Custom status code

```python
@login_required(status_code=403)
async def admin_panel(request: Request) -> JSONResponse:
    return JSONResponse({"admin": True})
```

### Redirect for HTML views

For server-rendered applications, redirect unauthenticated users to a login
page instead of returning a JSON error:

```python
@login_required(redirect_url="/login")
async def settings_page(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})
```

Unauthenticated requests receive a `302` redirect to `/login`.

---

## Using `require_auth()`

`require_auth()` is a synchronous helper for use inside route handlers. It
returns the authenticated user or raises `AuthenticationError`.

```python
from tortoise_auth.integrations.starlette import require_auth

async def my_route(request: Request) -> JSONResponse:
    user = require_auth(request)
    return JSONResponse({"email": user.email})
```

!!! tip "When to use `require_auth()` vs `login_required`"
    Use `login_required` when you want the decorator to handle the error
    response for you (JSON 401 or redirect). Use `require_auth()` when you need
    the user object and want to handle the `AuthenticationError` yourself -- for
    example in an exception handler or a more complex route.

---

## Custom scopes

By default, authenticated users receive the `("authenticated",)` scope. You can
customise this by passing a `scopes` tuple to the backend:

```python
backend = TokenAuthBackend(scopes=("authenticated", "api"))
```

Scopes are available in route handlers via `request.auth.scopes` and can be
used with Starlette's built-in `requires()` decorator:

```python
from starlette.authentication import requires

@requires("authenticated")
async def protected(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})
```

---

## Complete example

Below is a full, runnable Starlette application that demonstrates registration,
login, authenticated access, and logout.

```python
"""Starlette + tortoise-auth -- complete example."""

import asyncio

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from tortoise import Tortoise, fields

from tortoise_auth import AbstractUser, AuthConfig, AuthService, configure
from tortoise_auth.exceptions import AuthenticationError
from tortoise_auth.integrations.starlette import (
    TokenAuthBackend,
    login_required,
    require_auth,
)


# -- Model -------------------------------------------------------------------

class User(AbstractUser):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "users"


# -- Routes ------------------------------------------------------------------

async def register(request: Request) -> JSONResponse:
    """Create a new user account."""
    body = await request.json()
    user = await User.create(email=body["email"])
    await user.set_password(body["password"])
    return JSONResponse({"email": user.email}, status_code=201)


async def login(request: Request) -> JSONResponse:
    """Authenticate and return tokens."""
    body = await request.json()
    auth = AuthService()
    try:
        result = await auth.login(body["email"], body["password"])
    except AuthenticationError:
        return JSONResponse(
            {"detail": "Invalid credentials"}, status_code=401
        )
    return JSONResponse({
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
    })


@login_required
async def me(request: Request) -> JSONResponse:
    """Return the current user's profile."""
    return JSONResponse({
        "email": request.user.email,
        "is_verified": request.user.is_verified,
    })


async def logout(request: Request) -> JSONResponse:
    """Revoke the current access token."""
    user = require_auth(request)
    token = request.headers["Authorization"].split(" ", 1)[1]
    auth = AuthService()
    await auth.logout(token)
    return JSONResponse({"detail": "Logged out"})


# -- Application -------------------------------------------------------------

app = Starlette(
    routes=[
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/me", me),
        Route("/logout", logout, methods=["POST"]),
    ],
)
app.add_middleware(AuthenticationMiddleware, backend=TokenAuthBackend())


# -- Startup / Shutdown -------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    await Tortoise.init(
        db_url="sqlite://db.sqlite3",
        modules={
            "models": ["__main__"],
            "tortoise_auth": ["tortoise_auth.models"],
        },
    )
    await Tortoise.generate_schemas()
    configure(AuthConfig(
        user_model="models.User",
        signing_secret="change-me-in-production",
    ))


@app.on_event("shutdown")
async def shutdown() -> None:
    await Tortoise.close_connections()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Try it out

Start the server and test the endpoints with `curl`:

```bash
# Register
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "SecurePass123!"}'

# Login
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "SecurePass123!"}'

# Access protected route (replace <token> with the access_token from login)
curl http://localhost:8000/me \
  -H "Authorization: Bearer <token>"

# Logout
curl -X POST http://localhost:8000/logout \
  -H "Authorization: Bearer <token>"
```

---

## API reference

### `TokenAuthBackend`

```python
class TokenAuthBackend(AuthenticationBackend):
    def __init__(
        self,
        auth_service: AuthService | None = None,
        *,
        scopes: tuple[str, ...] = ("authenticated",),
    ) -> None: ...
```

| Parameter      | Type                     | Default              | Description                              |
|----------------|--------------------------|----------------------|------------------------------------------|
| `auth_service` | `AuthService \| None`    | `None`               | Service instance to use. If `None`, a new `AuthService()` is created lazily. |
| `scopes`       | `tuple[str, ...]`        | `("authenticated",)` | Scopes granted to authenticated users.   |

### `login_required`

```python
def login_required(
    fn: Callable | None = None,
    *,
    status_code: int = 401,
    redirect_url: str | None = None,
) -> Any: ...
```

| Parameter      | Type           | Default | Description                                              |
|----------------|----------------|---------|----------------------------------------------------------|
| `status_code`  | `int`          | `401`   | HTTP status code for unauthenticated JSON responses.     |
| `redirect_url` | `str \| None`  | `None`  | If set, redirect unauthenticated requests to this URL instead of returning JSON. |

### `require_auth`

```python
def require_auth(request: Request) -> Any
```

Returns the authenticated user from `request.user`. Raises
`AuthenticationError` if the user is not authenticated.

### `AnonymousUser`

Placeholder object set on `request.user` when no valid token is present.

| Property           | Returns |
|--------------------|---------|
| `is_authenticated` | `False` |
| `is_anonymous`     | `True`  |
| `display_name`     | `""`    |

---

## S2S authentication backend

For server-to-server authentication, use `S2SAuthBackend` instead of
`TokenAuthBackend`. See the dedicated
[S2S Authentication](../guides/s2s.md) guide for full details.

```python
from tortoise_auth.integrations.starlette import S2SAuthBackend

app.add_middleware(AuthenticationMiddleware, backend=S2SAuthBackend())
```

### `S2SAuthBackend`

```python
class S2SAuthBackend(AuthenticationBackend):
    def __init__(
        self,
        s2s_service: S2SService | None = None,
        *,
        scopes: tuple[str, ...] = ("authenticated", "s2s"),
        service_name_header: str | None = "X-Service-Name",
    ) -> None: ...
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `s2s_service` | `S2SService \| None` | `None` | Service instance to use. If `None`, a new `S2SService()` is created lazily. |
| `scopes` | `tuple[str, ...]` | `("authenticated", "s2s")` | Scopes granted to authenticated services. |
| `service_name_header` | `str \| None` | `"X-Service-Name"` | Header to read the calling service name from. Set to `None` to disable. |

### `require_s2s`

```python
def require_s2s(request: Request) -> ServiceIdentity
```

Returns the `ServiceIdentity` from `request.user`. Raises
`AuthenticationError` if the request is not S2S-authenticated.

### `ServiceIdentity`

Placeholder object set on `request.user` when a valid S2S token is present.

| Property | Returns |
|---|---|
| `is_authenticated` | `True` |
| `is_anonymous` | `False` |
| `display_name` | Service name or `"service"` |
| `service_name` | The `X-Service-Name` header value, or `None` |

---

Next step: learn about the core authentication service in the
[Authentication](../guides/authentication.md) guide.