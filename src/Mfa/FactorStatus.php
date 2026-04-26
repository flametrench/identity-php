<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Lifecycle status of a single factor.
 *
 * Pending — for TOTP/WebAuthn between enroll and confirmEnrollment.
 * Active — usable for verifyMfa. Recovery codes start active.
 * Suspended / Revoked — terminal-ish per ADR 0005 lifecycle.
 */
enum FactorStatus: string
{
    case Pending = 'pending';
    case Active = 'active';
    case Suspended = 'suspended';
    case Revoked = 'revoked';
}
