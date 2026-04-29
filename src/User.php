<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

final readonly class User
{
    public function __construct(
        public string $id,
        public Status $status,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
        /** v0.2 (ADR 0014) — optional human-meaningful render string. */
        public ?string $displayName = null,
    ) {}

    public function withStatus(Status $status, \DateTimeImmutable $updatedAt): self
    {
        return new self($this->id, $status, $this->createdAt, $updatedAt, $this->displayName);
    }
}
