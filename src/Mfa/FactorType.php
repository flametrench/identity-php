<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/** v0.2 factor variants (ADR 0008). */
enum FactorType: string
{
    case Totp = 'totp';
    case WebAuthn = 'webauthn';
    case Recovery = 'recovery';
}
