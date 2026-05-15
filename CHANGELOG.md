# Changelog

All notable changes to `flametrench/identity` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.0] — 2026-05-15

### Added (personal access tokens, ADR 0016)
- New `Flametrench\Identity\Pat\` namespace: `PersonalAccessToken` record, `PatStatus` enum, `VerifiedPat` verification result.
- New exceptions: `InvalidPatTokenException`, `PatExpiredException`, `PatRevokedException`. The "no such row" and "wrong secret" cases conflate to `InvalidPatTokenException` to avoid a token-presence timing oracle (ADR 0016 §"Verification semantics").
- New methods on `IdentityStore`: `createPat`, `getPat`, `listPatsForUser`, `revokePat`, `verifyPatToken`. Implemented in both `InMemoryIdentityStore` and `PostgresIdentityStore`.
- Wire format: `pat_<32hex-id>_<base64url-secret>` (Stripe-style id-then-secret). The plaintext token is returned ONCE in the `createPat` result and never again — the server stores only an Argon2id hash of the secret segment at the cred-password parameter floor (m=19456, t=2, p=1).
- New `patLastUsedCoalesceSeconds` constructor option on both stores (default 60s) to avoid a write-per-request hot path on the `last_used_at` column. 0 disables coalescing.
- `PostgresIdentityStore` PAT methods cooperate with outer transactions via `SAVEPOINT/RELEASE` (ADR 0013).
- Coverage: 21 in-memory tests + 17 Postgres integration tests.

### Required dependency bump
- `flametrench/ids` constraint now `^0.3.0` for the `pat` type prefix (ADR 0016).

## [v0.2.0] — 2026-04-30

### Released
- v0.2 stable cutoff. No functional changes from `v0.2.0-rc.5` — same source, version bumped to drop the `-rc` suffix at the spec v0.2.0 freeze. Published to Packagist `^0.2.0` constraint.

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
