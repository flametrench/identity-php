<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

final readonly class VerifiedCredential
{
    /**
     * @param bool $mfaRequired ``true`` when ``usr_mfa_policy.required`` is true
     *     AND the grace window has elapsed (or was never set). Applications
     *     MUST call ``verifyMfa`` before ``createSession`` when this is true.
     *     Defaults to ``false`` so adopters who never enable a policy see no
     *     behavioral change. (ADR 0008.)
     */
    public function __construct(
        public string $usrId,
        public string $credId,
        public bool $mfaRequired = false,
    ) {}
}
