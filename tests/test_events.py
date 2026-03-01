"""Tests for the event emitter."""

import pytest

from tortoise_auth.events import EventEmitter, emitter


@pytest.fixture(autouse=True)
def _clear_module_emitter():
    """Clear the module-level emitter before and after each test."""
    emitter.clear()
    yield
    emitter.clear()


class TestEventEmitter:
    async def test_register_and_emit(self):
        em = EventEmitter()
        calls = []

        async def handler(value):
            calls.append(value)

        em.add_listener("test", handler)
        await em.emit("test", 42)

        assert calls == [42]

    async def test_on_decorator(self):
        em = EventEmitter()
        calls = []

        @em.on("my_event")
        async def handler(x):
            calls.append(x)

        await em.emit("my_event", "hello")
        assert calls == ["hello"]

    async def test_multi_handlers_ordered(self):
        em = EventEmitter()
        order = []

        async def first():
            order.append(1)

        async def second():
            order.append(2)

        async def third():
            order.append(3)

        em.add_listener("evt", first)
        em.add_listener("evt", second)
        em.add_listener("evt", third)

        await em.emit("evt")
        assert order == [1, 2, 3]

    async def test_emit_no_listeners(self):
        em = EventEmitter()
        await em.emit("nonexistent")  # should not raise

    async def test_remove_listener(self):
        em = EventEmitter()
        calls = []

        async def handler():
            calls.append(1)

        em.add_listener("evt", handler)
        em.remove_listener("evt", handler)
        await em.emit("evt")

        assert calls == []

    async def test_remove_listener_not_found(self):
        em = EventEmitter()

        async def handler():
            pass

        with pytest.raises(ValueError):
            em.remove_listener("evt", handler)

    async def test_listeners_returns_copy(self):
        em = EventEmitter()

        async def handler():
            pass

        em.add_listener("evt", handler)
        listeners = em.listeners("evt")
        assert listeners == [handler]

        listeners.clear()
        assert em.listeners("evt") == [handler]

    async def test_clear_specific_event(self):
        em = EventEmitter()

        async def h1():
            pass

        async def h2():
            pass

        em.add_listener("a", h1)
        em.add_listener("b", h2)
        em.clear("a")

        assert em.listeners("a") == []
        assert em.listeners("b") == [h2]

    async def test_clear_all(self):
        em = EventEmitter()

        async def h():
            pass

        em.add_listener("a", h)
        em.add_listener("b", h)
        em.clear()

        assert em.listeners("a") == []
        assert em.listeners("b") == []


class TestErrorPropagation:
    async def test_errors_logged_by_default(self):
        em = EventEmitter(propagate_errors=False)

        async def bad_handler():
            raise RuntimeError("boom")

        em.add_listener("evt", bad_handler)
        await em.emit("evt")  # should not raise

    async def test_errors_propagated_when_enabled(self):
        from tortoise_auth.exceptions import EventError

        em = EventEmitter(propagate_errors=True)

        async def bad_handler():
            raise RuntimeError("boom")

        em.add_listener("evt", bad_handler)
        with pytest.raises(EventError) as exc_info:
            await em.emit("evt")

        assert exc_info.value.event_name == "evt"
        assert exc_info.value.handler_name == "bad_handler"
        assert isinstance(exc_info.value.original, RuntimeError)

    async def test_error_does_not_stop_other_handlers_when_not_propagated(self):
        em = EventEmitter(propagate_errors=False)
        calls = []

        async def bad():
            raise RuntimeError("boom")

        async def good():
            calls.append("ok")

        em.add_listener("evt", bad)
        em.add_listener("evt", good)
        await em.emit("evt")

        assert calls == ["ok"]


class TestModuleLevelEmitter:
    async def test_module_level_on_and_emit(self):
        from tortoise_auth.events import emit, on

        calls = []

        @on("test_mod")
        async def handler(val):
            calls.append(val)

        await emit("test_mod", "data")
        assert calls == ["data"]

    async def test_module_level_add_remove(self):
        from tortoise_auth.events import add_listener, emit, remove_listener

        calls = []

        async def handler():
            calls.append(1)

        add_listener("mod_evt", handler)
        await emit("mod_evt")
        assert calls == [1]

        remove_listener("mod_evt", handler)
        await emit("mod_evt")
        assert calls == [1]
