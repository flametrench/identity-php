<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

final readonly class VerifiedCredential
{
    public function __construct(
        public string $usrId,
        public string $credId,
    ) {}
}
