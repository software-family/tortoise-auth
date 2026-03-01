"""Async event emitter for tortoise-auth lifecycle hooks."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine
from typing import Any

from tortoise_auth.exceptions import EventError

logger = logging.getLogger(__name__)

Handler = Callable[..., Coroutine[Any, Any, Any]]


class EventEmitter:
    """Simple async event emitter with sequential handler execution."""

    def __init__(self, *, propagate_errors: bool = False) -> None:
        self.propagate_errors = propagate_errors
        self._listeners: dict[str, list[Handler]] = defaultdict(list)

    def on(self, event_name: str) -> Callable[[Handler], Handler]:
        """Decorator to register a handler for an event."""

        def decorator(handler: Handler) -> Handler:
            self.add_listener(event_name, handler)
            return handler

        return decorator

    def add_listener(self, event_name: str, handler: Handler) -> None:
        """Register a handler for an event."""
        self._listeners[event_name].append(handler)

    def remove_listener(self, event_name: str, handler: Handler) -> None:
        """Remove a handler for an event."""
        self._listeners[event_name].remove(handler)

    async def emit(self, event_name: str, *args: Any, **kwargs: Any) -> None:
        """Emit an event, calling all registered handlers sequentially."""
        for handler in self._listeners[event_name][:]:
            try:
                await handler(*args, **kwargs)
            except Exception as exc:
                error = EventError(event_name, handler.__name__, exc)
                if self.propagate_errors:
                    raise error from exc
                logger.error(str(error))

    def listeners(self, event_name: str) -> list[Handler]:
        """Return a copy of the listener list for an event."""
        return list(self._listeners[event_name])

    def clear(self, event_name: str | None = None) -> None:
        """Clear listeners. If event_name is None, clear all."""
        if event_name is None:
            self._listeners.clear()
        else:
            self._listeners.pop(event_name, None)


# Module-level emitter instance and convenience aliases
emitter = EventEmitter()
on = emitter.on
emit = emitter.emit
add_listener = emitter.add_listener
remove_listener = emitter.remove_listener
