# Changelog

All notable changes to `flametrench/identity` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.1] — 2026-06-06

### Fixed (security)
- **Timing oracle in `verifyPassword` (GHSA-33cx-f9xx-h6ff):** The method did not use a dummy Argon2id hash when credential lookups failed, allowing attackers to determine user existence through timing analysis. The vulnerability was introduced in v0.0.1 and affected all releases prior to v0.3.1. Adopters running any version `< 0.3.1` should upgrade immediately. See [GHSA-33cx-f9xx-h6ff](https://github.com/flametrench/identity-php/security/advisories/GHSA-33cx-f9xx-h6ff) for details.

## [v0.3.0] — 2026-06-05

*This release contained a security vulnerability (timing oracle in `verifyPassword`). Do not use; upgrade to v0.3.1.*

### Added
- PostgreSQL-backed `IdentityStore` and Postgres schema migrations (matching spec v0.3.0 conformance)
- [Additional v0.3.0 features documented in spec/CHANGELOG.md]

## [v0.2.0-rc.5] — 2026-04-27

### Fixed (security posture)
- `verifyPassword` now consults `usr_mfa_policy` and returns `VerifiedCredential::$mfaRequired = true` when a user has `required = true` AND the grace window has elapsed (or was never set). Previously the policy table was decorative — the SDK never read it, so an adopter configuring per-user MFA enforcement could be bypassed by application code that called `createSession` directly without checking the policy. The new field is additive (defaults to `false`), so adopters who do not configure a policy see no behavioral change. Applications MUST gate `createSession` on `mfaRequired` by calling `verifyMfa` first when it is `true`. (ADR 0008.)

## [v0.2.0-rc.4] — 2026-04-27

### Added
- `Flametrench\Identity\PostgresIdentityStore` — a Postgres-backed `IdentityStore`. Mirrors `InMemoryIdentityStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `usr`, `cred`, `ses`, `mfa`, `usr_mfa_policy` tables, plus `ses.mfa_verified_at`).
  - Connection: accepts a `PDO` instance. `ext-pdo` and `ext-pdo_pgsql` are listed under `suggest` rather than `require` — adopters using only the in-memory store don't need them.
  - Token storage: SHA-256 hashed and stored as 32 raw bytes (`BYTEA`). Plaintext tokens are returned ONCE on create/refresh and never persisted.
  - Multi-statement ops (`revokeUser` cascade, credential rotation, `refreshSession`, MFA confirm/verify, recovery-slot consumption) run inside a transaction.
  - Coverage: 23 integration tests, gated on `IDENTITY_POSTGRES_URL`.

## [v0.2.0-rc.3] — 2026-04-26

### Added (MFA store ops, ADR 0008 Phase 1)
- `enrollTotpFactor`, `enrollWebAuthnFactor`, `enrollRecoveryFactor`, `confirmTotpFactor`, `confirmWebAuthnFactor`, `revokeMfaFactor`, `verifyMfa`, `getMfaPolicy`, `setMfaPolicy` on `IdentityStore`. Wires the MFA primitives behind a single store-level surface so adopters don't write the orchestration themselves.

## [v0.2.0-rc.2] — 2026-04-26

WebAuthn RS256 + EdDSA assertion verification per ADR 0010.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate.

For pre-rc history, see git tags.
