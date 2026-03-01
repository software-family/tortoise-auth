# Events

tortoise-auth ships with an async event system that lets you react to
authentication lifecycle events -- successful logins, failed attempts,
logouts, and password changes -- without modifying library internals.
Register async handlers, and they will be called automatically whenever the
corresponding event is emitted.

The event system lives in `tortoise_auth.events`. All public names are also
re-exported from the top-level `tortoise_auth` package.

---

## Registering handlers

### The `@on` decorator

The most common way to subscribe to an event is the `@on` decorator. It takes
the event name as a string and registers the decorated async function as a
handler.

```python
from tortoise_auth.events import on


@on("user_login")
async def greet_user(user) -> None:
    """Log a message every time a user logs in."""
    print(f"Welcome back, {user.email}!")
```

The decorator returns the original function unchanged, so you can stack
multiple decorators or call the function directly in tests.

### `add_listener()`

If you need to register a handler programmatically -- for example, inside a
factory function or a framework startup hook -- use `add_listener()` instead.

```python
from tortoise_auth.events import add_listener


async def on_login(user) -> None:
    print(f"{user.email} just logged in.")


add_listener("user_login", on_login)
```

`@on("event_name")` and `add_listener("event_name", handler)` are
functionally identical. The decorator is syntactic sugar that calls
`add_listener` internally.

!!! note "Handler execution order"
    Handlers are called **sequentially** in the order they were registered,
    not concurrently. If handler A was registered before handler B, A will
    always finish before B starts.

---

## Built-in events

tortoise-auth emits the following events automatically. You do not need to
call `emit()` yourself for these -- the library handles it.

| Event                | Emitted by                  | Signature                                               | Description                                  |
|----------------------|-----------------------------|---------------------------------------------------------|----------------------------------------------|
| `user_login`         | `AuthService.login()`       | `handler(user)`                                         | After successful authentication and token creation. `user` is the model instance. |
| `user_login_failed`  | `AuthService.login()`       | `handler(*, identifier: str, reason: str)`              | After a login attempt fails. `reason` is one of `"not_found"`, `"inactive"`, or `"bad_password"`. |
| `user_logout`        | `AuthService.logout()` / `logout_all()` | `handler(user)`                            | After a token is revoked. `user` is the model instance. |
| `password_changed`   | `AbstractUser.set_password()` | `handler(user)`                                       | After the password hash is saved to the database. `user` is the model instance. |

!!! warning
    `user_login_failed` passes its arguments as **keyword-only** arguments
    (`identifier=..., reason=...`), not positional. Make sure your handler
    signature matches.

---

## Practical examples

### Login auditing

Record every login and failed login attempt to a database table:

```python
from tortoise_auth.events import on


@on("user_login")
async def audit_login(user) -> None:
    """Record a successful login in the audit log."""
    await AuditLog.create(
        event="login",
        user=user,
        detail=f"Successful login for {user.email}",
    )


@on("user_login_failed")
async def audit_failed_login(*, identifier: str, reason: str) -> None:
    """Record a failed login attempt in the audit log."""
    await AuditLog.create(
        event="login_failed",
        detail=f"Failed login for {identifier!r}: {reason}",
    )
```

### Sending notifications

Send an email whenever a user changes their password:

```python
from tortoise_auth.events import on


@on("password_changed")
async def notify_password_change(user) -> None:
    """Send a security notification after a password change."""
    await send_email(
        to=user.email,
        subject="Your password was changed",
        body="If you did not make this change, contact support immediately.",
    )
```

### Rate-limiting failed logins

Track failed login attempts and lock accounts after repeated failures:

```python
import logging

from tortoise_auth.events import on

logger = logging.getLogger(__name__)

# In-memory counter; use Redis or a database table in production.
_failure_counts: dict[str, int] = {}

MAX_FAILURES = 5


@on("user_login_failed")
async def track_failures(*, identifier: str, reason: str) -> None:
    """Increment the failure counter and deactivate the account if needed."""
    _failure_counts[identifier] = _failure_counts.get(identifier, 0) + 1
    count = _failure_counts[identifier]

    logger.warning("Login failure #%d for %r (reason: %s)", count, identifier, reason)

    if count >= MAX_FAILURES and reason == "bad_password":
        from myapp.models import User

        user = await User.filter(email=identifier).first()
        if user is not None:
            user.is_active = False
            await user.save(update_fields=["is_active"])
            logger.warning("Account %r locked after %d failures", identifier, count)


@on("user_login")
async def reset_failure_counter(user) -> None:
    """Clear the failure counter on successful login."""
    _failure_counts.pop(user.email, None)
```

---

## Error handling

By default, exceptions raised inside event handlers are **logged and
swallowed**. This prevents a broken handler from crashing the login flow or
any other operation that emits events.

```python
from tortoise_auth.events import on


@on("user_login")
async def flaky_handler(user) -> None:
    raise RuntimeError("something went wrong")


# AuthService.login() will still succeed. The error is logged via the
# standard logging module at ERROR level.
```

When the default emitter catches an error, it logs a message in this format:

```text
Handler 'flaky_handler' for event 'user_login' raised RuntimeError: something went wrong
```

### Propagating errors

If you want handler errors to bubble up -- for example, in tests or when a
handler performs a critical operation that must not fail silently -- create an
`EventEmitter` with `propagate_errors=True`:

```python
from tortoise_auth.events import EventEmitter
from tortoise_auth.exceptions import EventError

emitter = EventEmitter(propagate_errors=True)


@emitter.on("user_login")
async def critical_handler(user) -> None:
    raise RuntimeError("audit system down")


# When this emitter fires, it raises EventError instead of logging:
try:
    await emitter.emit("user_login", user)
except EventError as exc:
    print(exc.event_name)     # "user_login"
    print(exc.handler_name)   # "critical_handler"
    print(exc.original)       # RuntimeError("audit system down")
```

`EventError` exposes three attributes:

| Attribute      | Type        | Description                                    |
|----------------|-------------|------------------------------------------------|
| `event_name`   | `str`       | The name of the event that was being emitted.  |
| `handler_name` | `str`       | The `__name__` of the handler that raised.     |
| `original`     | `Exception` | The original exception raised by the handler.  |

!!! note
    When `propagate_errors=True`, the **first** handler that raises stops
    execution. Subsequent handlers for that event are not called.

    When `propagate_errors=False` (the default), a failing handler is skipped
    and the remaining handlers still execute.

---

## Managing listeners

### `remove_listener()`

Unregister a previously registered handler. Pass the exact same function
object that was registered.

```python
from tortoise_auth.events import add_listener, remove_listener


async def temporary_handler(user) -> None:
    print("This will only run once (manually removed).")


add_listener("user_login", temporary_handler)

# Later, when the handler is no longer needed:
remove_listener("user_login", temporary_handler)
```

If the handler is not found in the listener list for that event, a
`ValueError` is raised.

### `listeners()`

Inspect the currently registered handlers for an event. Returns a **copy** of
the internal list, so modifying it has no effect on the emitter.

```python
from tortoise_auth.events import emitter

handlers = emitter.listeners("user_login")
print(f"{len(handlers)} handler(s) registered for user_login")
```

### `clear()`

Remove all handlers for a specific event, or clear every event at once.

```python
from tortoise_auth.events import emitter

# Clear handlers for a single event:
emitter.clear("user_login")

# Clear all handlers for all events:
emitter.clear()
```

---

## Custom EventEmitter for isolation

The module-level `emitter` instance is a global singleton shared across the
entire application. This is convenient for production use, but it can cause
test pollution -- a handler registered in one test leaks into the next.

For **tests** or **isolated subsystems**, create a dedicated `EventEmitter`
instance:

```python
from tortoise_auth.events import EventEmitter

# Isolated emitter for a specific subsystem
notifications_emitter = EventEmitter()


@notifications_emitter.on("user_login")
async def send_welcome_push(user) -> None:
    await push_service.send(user, "Welcome back!")


# This handler is NOT registered on the global emitter.
# It only fires when notifications_emitter.emit() is called.
await notifications_emitter.emit("user_login", user)
```

### Testing with a clean emitter

Use `clear()` in your test setup and teardown to guarantee a clean slate:

```python
import pytest

from tortoise_auth.events import emitter


@pytest.fixture(autouse=True)
def _clear_events():
    """Ensure no handler leaks between tests."""
    emitter.clear()
    yield
    emitter.clear()


async def test_login_event_fires():
    calls: list = []

    @emitter.on("user_login")
    async def capture(user):
        calls.append(user)

    # ... trigger a login ...

    assert len(calls) == 1
```

Alternatively, use a throwaway `EventEmitter` per test to avoid touching the
global instance entirely:

```python
async def test_error_propagation():
    em = EventEmitter(propagate_errors=True)

    @em.on("user_login")
    async def bad_handler(user):
        raise RuntimeError("boom")

    with pytest.raises(EventError):
        await em.emit("user_login", mock_user)
```

---

## API summary

All functions below are available from `tortoise_auth.events`. The decorator
and listener functions are also importable from the top-level `tortoise_auth`
package.

| Function / Attribute               | Description                                                        |
|-------------------------------------|--------------------------------------------------------------------|
| `on(event_name)`                    | Decorator that registers an async handler for an event.            |
| `add_listener(event_name, handler)` | Register an async handler for an event (imperative form).          |
| `remove_listener(event_name, handler)` | Remove a previously registered handler.                         |
| `emit(event_name, *args, **kwargs)` | Emit an event, calling all registered handlers sequentially.       |
| `emitter`                           | The module-level `EventEmitter` instance (global singleton).       |
| `EventEmitter(propagate_errors=False)` | Create an independent emitter with optional error propagation.  |
