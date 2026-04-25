<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * WebAuthn passkey credential. The public key bytes are stored internally;
 * the public Credential exposes only `passkeySignCount` and `passkeyRpId`
 * (useful for display + audit) — never the public key.
 */
final readonly class PasskeyCredential implements Credential
{
    public function __construct(
        public string $id,
        public string $usrId,
        /** WebAuthn credential id, base64url-encoded. */
        public string $identifier,
        public Status $status,
        public ?string $replaces,
        public int $passkeySignCount,
        public string $passkeyRpId,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
    ) {}

    public function getId(): string { return $this->id; }
    public function getUsrId(): string { return $this->usrId; }
    public function getType(): CredentialType { return CredentialType::Passkey; }
    public function getIdentifier(): string { return $this->identifier; }
    public function getStatus(): Status { return $this->status; }
    public function getReplaces(): ?string { return $this->replaces; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getUpdatedAt(): \DateTimeImmutable { return $this->updatedAt; }
}
