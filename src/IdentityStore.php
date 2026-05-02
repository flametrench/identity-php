<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Contract every identity backend implements.
 *
 * Cascade guarantees (spec-required):
 *   - Revoking a user revokes every active credential AND terminates
 *     every active session.
 *   - Suspending a user terminates active sessions but preserves creds.
 *   - Rotating a credential terminates every session bound to the old.
 *   - Revoking or suspending a credential terminates every session
 *     bound to it.
 */
interface IdentityStore
{
    /**
     * Sentinel for {@see updateUser} partial-update semantics (ADR 0014).
     * Implementations re-export this constant.
     */
    public const UNSET = '__flametrench_unset__';

    // ─── Users ───

    /**
     * @param ?string $displayName v0.2 (ADR 0014) optional render string.
     */
    public function createUser(?string $displayName = null): User;
    public function getUser(string $usrId): User;

    /**
     * Partial update of v0.2 user metadata per ADR 0014.
     *
     * Pass {@see IdentityStore::UNSET} to skip a field; pass `null` to
     * clear it. Suspended users MAY be updated; revoked users raise
     * AlreadyTerminalException. Unknown ids raise NotFoundException.
     */
    public function updateUser(
        string $usrId,
        string|null $displayName = self::UNSET,
    ): User;

    /**
     * Paginated user enumeration introduced in v0.2 (ADR 0015).
     *
     * Adopters MUST gate the call site (sysadmin route or equivalent);
     * the SDK does not enforce authorization. Cursor and ordering match
     * `TenancyStore::listMembers`.
     *
     * @param ?string $query  Case-insensitive substring against active credential identifiers.
     * @param ?Status $status Filter by user status; null = no filter.
     * @return Page<User>
     */
    public function listUsers(
        ?string $cursor = null,
        int $limit = 50,
        ?string $query = null,
        ?Status $status = null,
    ): Page;

    public function suspendUser(string $usrId): User;
    public function reinstateUser(string $usrId): User;
    public function revokeUser(string $usrId): User;

    // ─── Credentials ───
    public function createPasswordCredential(
        string $usrId,
        string $identifier,
        string $password,
    ): PasswordCredential;

    public function createPasskeyCredential(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
    ): PasskeyCredential;

    public function createOidcCredential(
        string $usrId,
        string $identifier,
        string $oidcIssuer,
        string $oidcSubject,
    ): OidcCredential;

    public function getCredential(string $credId): Credential;

    /** @return list<Credential> */
    public function listCredentialsForUser(string $usrId): array;

    public function findCredentialByIdentifier(
        CredentialType $type,
        string $identifier,
    ): ?Credential;

    public function rotatePassword(string $credId, string $newPassword): PasswordCredential;
    public function rotatePasskey(string $credId, string $publicKey, int $signCount, string $rpId): PasskeyCredential;
    public function rotateOidc(string $credId, string $oidcIssuer, string $oidcSubject): OidcCredential;

    public function suspendCredential(string $credId): Credential;
    public function reinstateCredential(string $credId): Credential;
    public function revokeCredential(string $credId): Credential;

    public function verifyPassword(string $identifier, string $password): VerifiedCredential;

    // ─── Sessions ───
    public function createSession(string $usrId, string $credId, int $ttlSeconds): SessionWithToken;
    public function getSession(string $sesId): Session;

    /** @return Page<Session> */
    public function listSessionsForUser(string $usrId, ?string $cursor = null, int $limit = 50): Page;

    public function verifySessionToken(string $token): Session;

    public function refreshSession(string $sesId): SessionWithToken;
    public function revokeSession(string $sesId): Session;

    // ─── v0.2 MFA store operations (ADR 0008) ───

    /**
     * @return array{factor: \Flametrench\Identity\Mfa\TotpFactor, secretB32: string, otpauthUri: string}
     */
    public function enrollTotpFactor(string $usrId, string $identifier): array;

    /**
     * @return array{factor: \Flametrench\Identity\Mfa\WebAuthnFactor}
     *
     * @param  list<string>|null  $transports
     */
    public function enrollWebAuthnFactor(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
        ?string $aaguid = null,
        ?array $transports = null,
    ): array;

    /**
     * @return array{factor: \Flametrench\Identity\Mfa\RecoveryFactor, codes: list<string>}
     */
    public function enrollRecoveryFactor(string $usrId): array;

    public function confirmTotpFactor(string $mfaId, string $code): \Flametrench\Identity\Mfa\TotpFactor;

    public function confirmWebAuthnFactor(
        string $mfaId,
        string $authenticatorData,
        string $clientDataJson,
        string $signature,
        string $expectedChallenge,
        string $expectedOrigin,
    ): \Flametrench\Identity\Mfa\WebAuthnFactor;

    /**
     * @return list<\Flametrench\Identity\Mfa\TotpFactor|\Flametrench\Identity\Mfa\WebAuthnFactor|\Flametrench\Identity\Mfa\RecoveryFactor>
     */
    public function listMfaFactors(string $usrId): array;

    public function getMfaFactor(string $mfaId): \Flametrench\Identity\Mfa\TotpFactor|\Flametrench\Identity\Mfa\WebAuthnFactor|\Flametrench\Identity\Mfa\RecoveryFactor;

    public function revokeMfaFactor(string $mfaId): \Flametrench\Identity\Mfa\TotpFactor|\Flametrench\Identity\Mfa\WebAuthnFactor|\Flametrench\Identity\Mfa\RecoveryFactor;

    public function verifyMfa(
        string $usrId,
        \Flametrench\Identity\Mfa\MfaProof $proof,
    ): \Flametrench\Identity\Mfa\MfaVerifyResult;

    public function getMfaPolicy(string $usrId): ?\Flametrench\Identity\Mfa\UserMfaPolicy;

    public function setMfaPolicy(
        string $usrId,
        bool $required,
        ?\DateTimeImmutable $graceUntil = null,
    ): \Flametrench\Identity\Mfa\UserMfaPolicy;

    // ─── v0.3 personal access tokens (ADR 0016) ───

    /**
     * Mint a new personal access token for the user.
     *
     * Returns a tuple of the persisted record and the plaintext bearer
     * token in `pat_<32hex-id>_<base64url-secret>` form. The plaintext
     * token is returned ONCE; the server retains only an Argon2id hash
     * of the secret segment at the cred-password parameter floor.
     * Adopters MUST surface the plaintext to the user immediately and
     * never persist it server-side.
     *
     * @security Adopter MUST gate this call so the requesting
     * principal either owns $usrId OR is a sysadmin acting on the
     * user's behalf. The SDK does not enforce. Without route-layer
     * gating, any authenticated user can mint PATs in any other
     * user's name. (security-audit-v0.3.md H7.)
     *
     * @security Adopter MUST gate calls on $scope. The SDK persists
     * scope as opaque strings — it does NOT interpret them at
     * verifyPatToken time. Unlike `tup.relation` (which check()
     * enforces against the rule registry), scope is purely an audit
     * tag unless the adopter's request handler reads VerifiedPat::$scope
     * and gates the request. (security-audit-v0.3.md F5.)
     *
     * @param  string                $usrId     Owner of the new token.
     * @param  string                $name      Human-readable label, 1–120 Unicode code units.
     * @param  list<string>          $scope     Application-defined scope claims; may be empty.
     * @param  ?\DateTimeImmutable   $expiresAt Optional expiry. Null = no expiry.
     * @return array{pat: \Flametrench\Identity\Pat\PersonalAccessToken, token: string}
     */
    public function createPat(
        string $usrId,
        string $name,
        array $scope = [],
        ?\DateTimeImmutable $expiresAt = null,
    ): array;

    /**
     * @security Adopter MUST gate so the requesting principal either
     * owns the PAT (matches usrId of the row) OR is a sysadmin. The
     * SDK returns the row regardless — without gating an unauth /
     * wrong-principal request leaks the PAT's existence, scope, and
     * metadata. (security-audit-v0.3.md H7.)
     */
    public function getPat(string $patId): \Flametrench\Identity\Pat\PersonalAccessToken;

    /**
     * Cursor-paginated PAT list for a user. Mirrors the listMembers /
     * listUsers pagination shape. Default returns all statuses; pass a
     * specific PatStatus to filter.
     *
     * @security Adopter MUST gate so the requesting principal either
     * is $usrId OR is a sysadmin. Without gating, any caller can
     * enumerate any user's PATs. (security-audit-v0.3.md H7.)
     *
     * @return Page<\Flametrench\Identity\Pat\PersonalAccessToken>
     */
    public function listPatsForUser(
        string $usrId,
        ?string $cursor = null,
        int $limit = 50,
        ?\Flametrench\Identity\Pat\PatStatus $status = null,
    ): Page;

    /**
     * Terminal-state revoke. Idempotent: revoking an already-revoked
     * token returns the existing row unchanged.
     *
     * @security Adopter MUST gate so the requesting principal either
     * owns the PAT OR is a sysadmin. Without gating, any caller can
     * revoke any user's PAT — locking the legitimate owner out of
     * their own automation. (security-audit-v0.3.md H7.)
     */
    public function revokePat(string $patId): \Flametrench\Identity\Pat\PersonalAccessToken;

    /**
     * Verify a PAT bearer token per ADR 0016 §"Verification semantics".
     *
     * Throws InvalidPatTokenException for malformed tokens, missing
     * rows, or wrong-secret matches (the missing/wrong cases MUST
     * conflate). Throws PatRevokedException for terminal-revoked
     * tokens. Throws PatExpiredException for past-expiry tokens.
     *
     * On success, side-effect: updates the row's last_used_at column.
     * Implementations MAY coalesce these writes within a configurable
     * window (60s default) to avoid a write-per-request hot path.
     */
    public function verifyPatToken(string $token): \Flametrench\Identity\Pat\VerifiedPat;
}
