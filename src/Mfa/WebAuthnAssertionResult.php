<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Successful WebAuthn assertion verification result.
 *
 * The new sign count MUST be persisted atomically with the session
 * decision; otherwise a race lets a cloned authenticator slip through.
 */
final readonly class WebAuthnAssertionResult
{
    public function __construct(public int $newSignCount) {}
}
