<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

final readonly class RecoveryFactor
{
    public FactorType $type;

    public function __construct(
        public string $id,
        public string $usrId,
        public FactorStatus $status,
        public ?string $replaces,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
        public int $remaining,
    ) {
        $this->type = FactorType::Recovery;
    }
}
