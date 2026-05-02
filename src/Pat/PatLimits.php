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

    private function __construct() {}
}
