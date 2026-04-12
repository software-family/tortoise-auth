"""CLI to create an invitation and print the onboarding link.

Usage:
    python -m examples.starlette_example.invite <email> [role] [--invited-by <email>]

Examples:
    python -m examples.starlette_example.invite admin@example.com
    python -m examples.starlette_example.invite alice@example.com owner
    python -m examples.starlette_example.invite alice@example.com --invited-by admin@example.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from tortoise import Tortoise

from examples.starlette_example.passkey_admin import (
    PUBLIC_BASE_URL,
    TORTOISE_DB_URL,
    TORTOISE_MODULES,
    User,
    invitation_service,
)


async def main() -> int:
    parser = argparse.ArgumentParser(
        prog="invite",
        description="Create an invitation and print a one-click onboarding link.",
    )
    parser.add_argument("email", help="Email address of the invitee")
    parser.add_argument("role", nargs="?", default="", help="Optional role tag (free-form string)")
    parser.add_argument(
        "--invited-by",
        default="",
        help="Email of the inviting admin (recorded for audit; not validated)",
    )
    args = parser.parse_args()

    await Tortoise.init(
        db_url=TORTOISE_DB_URL,
        modules=TORTOISE_MODULES,
        _enable_global_fallback=True,
    )
    try:
        await Tortoise.generate_schemas()

        invited_by = args.invited_by
        if invited_by:
            inviter = await User.filter(email=invited_by).first()
            invited_by = str(inviter.pk) if inviter else invited_by

        token = await invitation_service.create_invitation(
            args.email,
            invited_by=invited_by,
            role=args.role,
        )
    finally:
        await Tortoise.close_connections()

    link = f"{PUBLIC_BASE_URL}/onboarding?token={token}"
    print()
    print(f"Invitation created for: {args.email}")
    if args.role:
        print(f"Role:                   {args.role}")
    print("Expires in:             24 hours")
    print()
    print("Send this link to the invitee:")
    print(f"  {link}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
