<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

final readonly class TotpProof implements MfaProof
{
    public function __construct(public string $code) {}
}
