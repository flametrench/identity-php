<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

final readonly class OidcCredential implements Credential
{
    public function __construct(
        public string $id,
        public string $usrId,
        public string $identifier,
        public Status $status,
        public ?string $replaces,
        public string $oidcIssuer,
        public string $oidcSubject,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
    ) {}

    public function getId(): string { return $this->id; }
    public function getUsrId(): string { return $this->usrId; }
    public function getType(): CredentialType { return CredentialType::Oidc; }
    public function getIdentifier(): string { return $this->identifier; }
    public function getStatus(): Status { return $this->status; }
    public function getReplaces(): ?string { return $this->replaces; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getUpdatedAt(): \DateTimeImmutable { return $this->updatedAt; }
}
