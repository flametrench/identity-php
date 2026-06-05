<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Static helpers for PAT wire-format validation and bearer classification
 * per ADR 0016 §"Wire format" and §"Bearer routing".
 */
final class Pat
{
    /** Max lifetime cap per ADR 0016 §"Constraints": 365 days in seconds. */
    public const MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

    /**
     * Pre-rejection cap on the secret-segment length (security-audit-v0.3.md H6).
     * Real PAT secrets are 43 chars (32 bytes base64url); 256 leaves a
     * generous margin while bounding the DoS attack surface on Argon2id.
     */
    public const MAX_SECRET_LENGTH = 256;

    /**
     * Canonical dummy Argon2id PHC string used by verifyPatToken on the
     * missing-row path so "no such pat_id" is timing-indistinguishable from
     * "row exists but wrong secret" (security-audit-v0.3.md H2).
     *
     * Hash verifies against "correcthorsebatterystaple" at spec-floor params
     * (m=19456, t=2, p=1).  Pinned by spec/conformance/fixtures/identity/argon2id.json.
     */
    public const DUMMY_PHC_HASH =
        '$argon2id$v=19$m=19456,t=2,p=1$'
        . '779z4UHkLWR4w0TEo9gcHg$'
        . 'Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU';

    /** Wire-format regex per ADR 0016 §"Wire format". */
    private const WIRE_FORMAT = '/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/';

    /**
     * Pure structural check per ADR 0016 §"Wire format".
     * Returns true iff token matches pat_<32hex>_<base64url>.
     * Does NOT hit the database or Argon2id verifier.
     */
    public static function isStructurallyValid(string $token): bool
    {
        return preg_match(self::WIRE_FORMAT, $token) === 1;
    }

    /**
     * Pure prefix classifier per ADR 0016 §"Bearer routing".
     * Returns the auth.kind discriminator without invoking any verifier or
     * DB lookup.  The conformance fixture bearer-prefix-routing.json pins
     * the exact rules every SDK MUST produce identically.
     */
    public static function classifyBearer(string $token): AuthKind
    {
        if (str_starts_with($token, 'pat_')) {
            return AuthKind::Pat;
        }
        if (str_starts_with($token, 'shr_')) {
            return AuthKind::Share;
        }
        return AuthKind::Session;
    }
}
