<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

final readonly class Session
{
    public function __construct(
        public string $id,
        public string $usrId,
        public string $credId,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $revokedAt,
    ) {}

    public function withRevokedAt(\DateTimeImmutable $at): self
    {
        return new self(
            id: $this->id,
            usrId: $this->usrId,
            credId: $this->credId,
            createdAt: $this->createdAt,
            expiresAt: $this->expiresAt,
            revokedAt: $at,
        );
    }
}
