<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Inputs for verifying a WebAuthn assertion against a stored factor.
 *
 * `credentialId` matches the `identifier` field on the WebAuthn factor
 * (base64url-encoded WebAuthn credential ID). The store uses it to
 * locate the factor; the assertion bytes are verified against the
 * stored COSE public key.
 */
final readonly class WebAuthnProof implements MfaProof
{
    public function __construct(
        public string $credentialId,
        public string $authenticatorData,
        public string $clientDataJson,
        public string $signature,
        public string $expectedChallenge,
        public string $expectedOrigin,
    ) {}
}
