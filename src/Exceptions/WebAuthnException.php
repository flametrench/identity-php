<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Base class for WebAuthn assertion verification errors.
 *
 * Each subclass carries a stable `reason` token (signature_invalid,
 * counter_regression, rp_id_mismatch, ...) and an OpenAPI-style code
 * `webauthn.<reason>`.
 */
class WebAuthnException extends IdentityException
{
    public function __construct(string $message, public readonly string $reason)
    {
        parent::__construct($message, "webauthn.{$reason}");
    }
}
