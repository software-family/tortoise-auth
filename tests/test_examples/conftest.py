"""Local conftest for the Starlette passkey-admin example tests.

Overrides the global ``init_db`` fixture so the example's ``User`` model is
included in the Tortoise registry under the ``models`` app label.
"""

from __future__ import annotations

import pytest_asyncio
from tortoise.context import tortoise_test_context


@pytest_asyncio.fixture(scope="function", autouse=True)
async def init_db():
    """Initialize a fresh Tortoise context including the example's User model."""
    async with tortoise_test_context(
        modules=[
            "examples.starlette_example.passkey_admin",
            "tortoise_auth.models.invitation",
            "tortoise_auth.models.jwt_blacklist",
            "tortoise_auth.models.onboarding",
            "tortoise_auth.models.passkey",
            "tortoise_auth.models.rate_limit",
            "tortoise_auth.models.tokens",
        ],
        db_url="sqlite://:memory:",
    ) as ctx:
        yield ctx
