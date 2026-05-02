<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Pat;

/**
 * Spec-pinned constants for the PAT primitive (ADR 0016).
 *
 * Implementations MAY enforce tighter caps than these. Adopters SHOULD
 * NOT depend on the floor values being exactly these — read them from
 * the constants below if needed.
 */
final class PatLimits
{
    /**
     * Spec floor: PAT `expires_at` MUST be no more than 365 days from
     * `created_at` when set (ADR 0016 §"Constraints").
     * 365 days = 31,536,000 seconds.
     */
    public const MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

    /**
     * security-audit-v0.3.md H2 — the dummy PHC hash used by
     * verifyPatToken on the missing-row path so the wall-clock time
     * of "no such pat_id" is indistinguishable from "row exists but
     * wrong secret." Without this, an attacker can probe pat_id
     * existence via timing without knowing the secret.
     *
     * The same hash is in spec/conformance/fixtures/identity/argon2id.json
     * (verifies to "correcthorsebatterystaple"). Generated with the
     * spec floor parameters (m=19456, t=2, p=1). PAT secrets are
     * 43-char base64url strings (32 bytes) — collision probability
     * with the dummy plaintext is vanishing.
     */
    public const DUMMY_PHC_HASH = '$argon2id$v=19$m=19456,t=2,p=1$779z4UHkLWR4w0TEo9gcHg$Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU';

    private function __construct() {}
}
