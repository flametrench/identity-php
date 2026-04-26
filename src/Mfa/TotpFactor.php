<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

final readonly class TotpFactor
{
    public FactorType $type;

    public function __construct(
        public string $id,
        public string $usrId,
        public string $identifier,
        public FactorStatus $status,
        public ?string $replaces,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
    ) {
        $this->type = FactorType::Totp;
    }
}
