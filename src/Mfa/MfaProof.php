<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Marker interface for an MFA verification proof.
 *
 * Implemented by {@see TotpProof}, {@see WebAuthnProof}, and
 * {@see RecoveryProof}. Stores dispatch on the concrete subclass.
 */
interface MfaProof {}
