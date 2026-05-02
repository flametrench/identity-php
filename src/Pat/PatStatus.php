<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Pat;

/**
 * Lifecycle status of a personal access token (ADR 0016).
 *
 * Active — present, not expired, not revoked.
 * Expired — past expires_at. Terminal.
 * Revoked — revokePat called. Terminal.
 *
 * A PAT cannot return to Active once it leaves it; re-issuance creates
 * a new pat row, NOT a replaces-chain entry (PATs are bearer secrets,
 * not interactive credentials with identity continuity to preserve).
 */
enum PatStatus: string
{
    case Active = 'active';
    case Expired = 'expired';
    case Revoked = 'revoked';
}
