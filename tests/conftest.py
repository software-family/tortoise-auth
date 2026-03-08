import pytest_asyncio
from tortoise.context import tortoise_test_context


@pytest_asyncio.fixture(scope="function", autouse=True)
async def init_db():
    """Initialize an in-memory SQLite database for each test."""
    async with tortoise_test_context(
        modules=[
            "tests.models",
            "tortoise_auth.models.jwt_blacklist",
            "tortoise_auth.models.rate_limit",
            "tortoise_auth.models.tokens",
        ],
        db_url="sqlite://:memory:",
    ) as ctx:
        yield ctx
