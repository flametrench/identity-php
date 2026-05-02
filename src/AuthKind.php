<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Audit `auth.kind` discriminator values per ADR 0016 §"Bearer routing".
 *
 * security-audit-v0.3.md F3: pre-fix the four canonical values
 * (pat / share / session / system) lived only in spec prose with no
 * SDK constant. Adopters writing cron / scheduled jobs reach for
 * `'pat'` or `'session'` because those exist as code values; `'system'`
 * (operator-initiated, no human bearer) did not. This class centralizes
 * the constants so adopters can `AuthKind::SYSTEM` instead of
 * stringly-typing across an audit pipeline.
 *
 * The `pat`, `share`, and `session` values are minted by the bearer
 * dispatcher / verifiers; `system` is set directly by adopter code
 * (cron jobs, batch processors, scheduled tasks).
 */
final class AuthKind
{
    public const PAT = 'pat';
    public const SHARE = 'share';
    public const SESSION = 'session';
    public const SYSTEM = 'system';

    private function __construct() {}
}
