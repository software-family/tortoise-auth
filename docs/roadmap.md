# Roadmap

An overview of what tortoise-auth ships today and where the project is headed.

---

## Current Status (v0.4.0)

The following features are implemented and available in the current release:

- **AbstractUser model** -- email field, password hashing, `is_active` and
  `is_verified` flags.
- **AuthService** -- high-level async API covering `login`, `authenticate`,
  `refresh`, `logout`, and `logout_all`.
- **Database token backend** -- server-side tokens stored in Tortoise ORM with
  SHA-256 hashing and full revocation support.
- **Password hashing** -- Argon2id (primary), Bcrypt, and PBKDF2-SHA256 with
  transparent auto-migration to the strongest hasher.
- **Password validation** -- four built-in validators (minimum length, common
  password list, numeric-only, user-attribute similarity) plus custom validators
  via the `PasswordValidator` Protocol.
- **HMAC signing** -- `Signer`, `TimestampSigner`, and convenience helpers
  `make_token` / `verify_token` for signed payloads.
- **Event system** -- async handlers for `user_login`, `user_login_failed`,
  `user_logout`, and `password_changed` events.
- **Global configuration** -- single `AuthConfig` dataclass to configure the
  entire library.
- **Rate limiting** -- pluggable backends (in-memory and database) for login
  attempt throttling. Starlette middleware included.
- **Onboarding flow engine** -- server-driven, multi-step onboarding with a
  state machine that guides the client through register → verify email → TOTP
  setup → profile completion. Pluggable via the `OnboardingStep` Protocol.
  Built-in steps: `RegisterStep`, `VerifyEmailStep`, `SetupTOTPStep`,
  `ProfileCompletionStep`.
- **Server-to-server authentication** -- `S2SService` for service-to-service
  communication using env-var-based static bearer tokens with constant-time
  comparison and comma-separated token rotation. Starlette `S2SAuthBackend`
  included.

## Planned Features

These features are on the roadmap and under active consideration:

- **Password reset flow** -- secure token-based password reset with configurable
  expiry.
- **API key authentication** -- long-lived keys for service-to-service or
  programmatic access.
- **Framework integrations** -- first-party middleware and dependency injection
  for FastAPI, Starlette, and Litestar.

!!! note "No guarantees on ordering"
    The features above are listed roughly in order of priority, but timelines
    may shift based on community feedback and contributor availability.

## Contributing

Contributions, bug reports, and feature requests are welcome. Visit the
[GitHub repository](https://github.com/elie/tortoise-auth) to open an issue or
submit a pull request.
