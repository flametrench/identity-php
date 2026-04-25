<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Returned from createSession / refreshSession. The bearer token is
 * separate from the session id (per spec) and is the only chance to
 * capture it — implementations store only its SHA-256 hash.
 */
final readonly class SessionWithToken
{
    public function __construct(
        public Session $session,
        public string $token,
    ) {}
}
