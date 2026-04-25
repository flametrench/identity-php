<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Argon2id parameter floors required by the Flametrench v0.1 specification.
 * Implementations MUST use values at or above these. See spec/docs/identity.md
 * §"Hashing requirements" and ADR 0004.
 */
final class Argon2id
{
    /** Minimum memory cost in KiB (= 19 MiB). */
    public const MEMORY_COST = 19456;

    /** Minimum time cost (iterations). */
    public const TIME_COST = 2;

    /** Minimum parallelism (threads). */
    public const THREADS = 1;

    private function __construct() {}
}
