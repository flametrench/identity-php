<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Identity\CredentialType;
use Flametrench\Identity\Exceptions\AlreadyTerminalException;
use Flametrench\Identity\Exceptions\CredentialNotActiveException;
use Flametrench\Identity\Exceptions\DuplicateCredentialException;
use Flametrench\Identity\Exceptions\InvalidCredentialException;
use Flametrench\Identity\Exceptions\InvalidTokenException;
use Flametrench\Identity\Exceptions\NotFoundException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\Exceptions\SessionExpiredException;
use Flametrench\Identity\Mfa\FactorStatus;
use Flametrench\Identity\Mfa\FactorType;
use Flametrench\Identity\Mfa\RecoveryCodes;
use Flametrench\Identity\Mfa\RecoveryFactor;
use Flametrench\Identity\Mfa\RecoveryProof;
use Flametrench\Identity\Mfa\Totp;
use Flametrench\Identity\Mfa\TotpProof;
use Flametrench\Identity\PasskeyCredential;
use Flametrench\Identity\PasswordCredential;
use Flametrench\Identity\PostgresIdentityStore;
use Flametrench\Identity\Status;
use Flametrench\Ids\Id;

$identityPostgresUrl = getenv('IDENTITY_POSTGRES_URL') ?: null;

if ($identityPostgresUrl === null) {
    fwrite(STDERR, "[PostgresIdentityStoreTest] IDENTITY_POSTGRES_URL not set; tests skipped.\n");
    return;
}

beforeEach(function () use ($identityPostgresUrl) {
    $pdo = identityPgPdoFromUrl($identityPostgresUrl);
    $this->pdo = $pdo;
    $pdo->exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    $pdo->exec((string) file_get_contents(__DIR__ . '/postgres-schema.sql'));
    $this->store = new PostgresIdentityStore($pdo);
});

// ───── Users ─────

it('createUser yields a fresh active usr_ id', function () {
    $u = $this->store->createUser();
    expect($u->id)->toMatch('/^usr_[0-9a-f]{32}$/');
    expect($u->status)->toBe(Status::Active);
});

it('getUser raises NotFoundException for unknown ids', function () {
    $this->store->getUser(Id::generate('usr'));
})->throws(NotFoundException::class);

it('suspend → reinstate round-trip', function () {
    $u = $this->store->createUser();
    $suspended = $this->store->suspendUser($u->id);
    expect($suspended->status)->toBe(Status::Suspended);
    $reinstated = $this->store->reinstateUser($u->id);
    expect($reinstated->status)->toBe(Status::Active);
});

it('revokeUser cascades to credentials and sessions', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'pw');
    $session = $this->store->createSession($u->id, $cred->id, 3600);
    $this->store->revokeUser($u->id);
    expect($this->store->getUser($u->id)->status)->toBe(Status::Revoked);
    expect($this->store->getCredential($cred->id)->getStatus())->toBe(Status::Revoked);
    expect($this->store->getSession($session->session->id)->revokedAt)->not->toBeNull();
});

it('double-revoke is rejected', function () {
    $u = $this->store->createUser();
    $this->store->revokeUser($u->id);
    $this->store->revokeUser($u->id);
})->throws(AlreadyTerminalException::class);

// ───── Credentials ─────

it('creates a password credential and verifyPassword round-trips', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'correct horse battery staple');
    expect($cred)->toBeInstanceOf(PasswordCredential::class);
    $verified = $this->store->verifyPassword('alice@example.com', 'correct horse battery staple');
    expect($verified->usrId)->toBe($u->id);
    expect($verified->credId)->toBe($cred->id);
});

it('verifyPassword rejects a wrong password', function () {
    $u = $this->store->createUser();
    $this->store->createPasswordCredential($u->id, 'alice@example.com', 'pw');
    $this->store->verifyPassword('alice@example.com', 'wrong');
})->throws(InvalidCredentialException::class);

it('rejects a duplicate active credential on the same (type, identifier)', function () {
    $u = $this->store->createUser();
    $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p1');
    $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p2');
})->throws(DuplicateCredentialException::class);

it('rotatePassword revokes old, inserts new with replaces, terminates sessions', function () {
    $u = $this->store->createUser();
    $oldCred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'old');
    $session = $this->store->createSession($u->id, $oldCred->id, 3600);
    $newCred = $this->store->rotatePassword($oldCred->id, 'new');
    expect($newCred->replaces)->toBe($oldCred->id);
    expect($this->store->getCredential($oldCred->id)->getStatus())->toBe(Status::Revoked);
    expect($this->store->getSession($session->session->id)->revokedAt)->not->toBeNull();

    expect(fn() => $this->store->verifyPassword('alice@example.com', 'old'))
        ->toThrow(InvalidCredentialException::class);
    $verified = $this->store->verifyPassword('alice@example.com', 'new');
    expect($verified->credId)->toBe($newCred->id);
});

it('findCredentialByIdentifier returns active only', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $found = $this->store->findCredentialByIdentifier(CredentialType::Password, 'alice@example.com');
    expect($found?->getId())->toBe($cred->id);
    $this->store->revokeCredential($cred->id);
    expect($this->store->findCredentialByIdentifier(CredentialType::Password, 'alice@example.com'))
        ->toBeNull();
});

// ───── Sessions ─────

it('createSession returns a token distinct from the session id and verifies', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $sw = $this->store->createSession($u->id, $cred->id, 3600);
    expect($sw->token)->not->toBe($sw->session->id);
    $verified = $this->store->verifySessionToken($sw->token);
    expect($verified->id)->toBe($sw->session->id);
});

it('verifySessionToken rejects an unknown token', function () {
    $this->store->verifySessionToken('nope');
})->throws(InvalidTokenException::class);

it('verifySessionToken rejects a revoked session token', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $sw = $this->store->createSession($u->id, $cred->id, 3600);
    $this->store->revokeSession($sw->session->id);
    $this->store->verifySessionToken($sw->token);
})->throws(SessionExpiredException::class);

it('refreshSession returns a new session with a fresh token', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $sw = $this->store->createSession($u->id, $cred->id, 3600);
    $refreshed = $this->store->refreshSession($sw->session->id);
    expect($refreshed->session->id)->not->toBe($sw->session->id);
    expect($refreshed->token)->not->toBe($sw->token);
    expect($this->store->getSession($sw->session->id)->revokedAt)->not->toBeNull();
});

it('createSession rejects TTL below 60 seconds', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $this->store->createSession($u->id, $cred->id, 30);
})->throws(PreconditionException::class);

it('createSession rejects a suspended credential', function () {
    $u = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($u->id, 'alice@example.com', 'p');
    $this->store->suspendCredential($cred->id);
    $this->store->createSession($u->id, $cred->id, 3600);
})->throws(CredentialNotActiveException::class);

// ───── MFA ─────

it('enrollTotpFactor → confirmTotpFactor → verifyMfa round-trips', function () {
    $u = $this->store->createUser();
    $enroll = $this->store->enrollTotpFactor($u->id, 'iPhone');
    expect($enroll['factor']->status)->toBe(FactorStatus::Pending);
    expect(strlen($enroll['secretB32']))->toBeGreaterThan(0);
    expect(str_starts_with($enroll['otpauthUri'], 'otpauth://totp/'))->toBeTrue();

    $secretBytes = base32Decode($enroll['secretB32']);
    $code = Totp::compute($secretBytes, time());

    $active = $this->store->confirmTotpFactor($enroll['factor']->id, $code);
    expect($active->status)->toBe(FactorStatus::Active);

    $result = $this->store->verifyMfa($u->id, new TotpProof($code));
    expect($result->type)->toBe(FactorType::Totp);
    expect($result->mfaId)->toBe($active->id);
});

it('enforces at-most-one active TOTP factor per user', function () {
    $u = $this->store->createUser();
    $first = $this->store->enrollTotpFactor($u->id, 'iPhone');
    $code = Totp::compute(base32Decode($first['secretB32']), time());
    $this->store->confirmTotpFactor($first['factor']->id, $code);
    $this->store->enrollTotpFactor($u->id, 'Yubico');
})->throws(PreconditionException::class);

it('recovery codes verify once and then are consumed', function () {
    $u = $this->store->createUser();
    $enroll = $this->store->enrollRecoveryFactor($u->id);
    expect($enroll['codes'])->toHaveCount(10);
    $first = $enroll['codes'][0];
    $result = $this->store->verifyMfa($u->id, new RecoveryProof($first));
    expect($result->type)->toBe(FactorType::Recovery);
    // Same code reused → fail.
    expect(fn() => $this->store->verifyMfa($u->id, new RecoveryProof($first)))
        ->toThrow(InvalidCredentialException::class);
    // Remaining drops.
    $factors = $this->store->listMfaFactors($u->id);
    $recovery = array_values(array_filter($factors, fn($f) => $f->type === FactorType::Recovery))[0];
    expect($recovery)->toBeInstanceOf(RecoveryFactor::class);
    expect($recovery->remaining)->toBe(9);
});

it('recovery factor rejects malformed input', function () {
    $u = $this->store->createUser();
    $this->store->enrollRecoveryFactor($u->id);
    $this->store->verifyMfa($u->id, new RecoveryProof('not-a-code'));
})->throws(InvalidCredentialException::class);

it('revokeMfaFactor frees up the singleton slot', function () {
    $u = $this->store->createUser();
    $first = $this->store->enrollTotpFactor($u->id, 'iPhone');
    $code = Totp::compute(base32Decode($first['secretB32']), time());
    $this->store->confirmTotpFactor($first['factor']->id, $code);
    $this->store->revokeMfaFactor($first['factor']->id);
    $second = $this->store->enrollTotpFactor($u->id, 'Yubico');
    expect($second['factor']->status)->toBe(FactorStatus::Pending);
});

it('setMfaPolicy upserts and getMfaPolicy round-trips', function () {
    $u = $this->store->createUser();
    expect($this->store->getMfaPolicy($u->id))->toBeNull();
    $grace = new \DateTimeImmutable('+14 days');
    $set1 = $this->store->setMfaPolicy($u->id, required: true, graceUntil: $grace);
    expect($set1->required)->toBeTrue();
    expect($set1->graceUntil?->format('Y-m-d'))->toBe($grace->format('Y-m-d'));
    $fetched = $this->store->getMfaPolicy($u->id);
    expect($fetched?->required)->toBeTrue();
    // Upsert: clear grace.
    $set2 = $this->store->setMfaPolicy($u->id, required: true);
    expect($set2->graceUntil)->toBeNull();
});

it('getMfaPolicy throws NotFoundException for unknown user', function () {
    $this->store->getMfaPolicy(Id::generate('usr'));
})->throws(NotFoundException::class);

// ───── listUsers (ADR 0015) ─────

it('listUsers returns all users in id ASC order', function () {
    $a = $this->store->createUser();
    $b = $this->store->createUser();
    $c = $this->store->createUser();
    $page = $this->store->listUsers();
    $ids = array_map(fn($u) => $u->id, $page->data);
    expect($ids)->toEqual([$a->id, $b->id, $c->id]);
    expect($page->nextCursor)->toBeNull();
});

it('listUsers status filter excludes other states', function () {
    $active = $this->store->createUser();
    $suspended = $this->store->createUser();
    $this->store->suspendUser($suspended->id);
    $page = $this->store->listUsers(status: Status::Active);
    $ids = array_map(fn($u) => $u->id, $page->data);
    expect($ids)->toEqual([$active->id]);
});

it('listUsers query is case-insensitive substring against active credential identifiers', function () {
    $alice = $this->store->createUser();
    $this->store->createPasswordCredential($alice->id, 'alice@example.com', 'long-enough-password');
    $bob = $this->store->createUser();
    $this->store->createPasswordCredential($bob->id, 'bob@example.com', 'long-enough-password');
    $carol = $this->store->createUser();
    $this->store->createPasswordCredential($carol->id, 'carol@other.test', 'long-enough-password');

    $page = $this->store->listUsers(query: 'EXAMPLE');
    $ids = array_map(fn($u) => $u->id, $page->data);
    expect($ids)->toEqualCanonicalizing([$alice->id, $bob->id]);
});

it('listUsers query skips revoked credentials', function () {
    $alice = $this->store->createUser();
    $cred = $this->store->createPasswordCredential($alice->id, 'gone@example.com', 'long-enough-password');
    $this->store->revokeCredential($cred->id);
    $page = $this->store->listUsers(query: 'gone@example.com');
    expect($page->data)->toBeEmpty();
});

it('listUsers cursor walks pages', function () {
    $ids = [];
    for ($i = 0; $i < 5; $i++) {
        $ids[] = $this->store->createUser()->id;
    }
    $page1 = $this->store->listUsers(limit: 2);
    expect(array_map(fn($u) => $u->id, $page1->data))->toEqual([$ids[0], $ids[1]]);
    $page2 = $this->store->listUsers(cursor: $page1->nextCursor, limit: 2);
    expect(array_map(fn($u) => $u->id, $page2->data))->toEqual([$ids[2], $ids[3]]);
    $page3 = $this->store->listUsers(cursor: $page2->nextCursor, limit: 2);
    expect(array_map(fn($u) => $u->id, $page3->data))->toEqual([$ids[4]]);
    expect($page3->nextCursor)->toBeNull();
});

it('listUsers on empty install returns empty page', function () {
    $page = $this->store->listUsers();
    expect($page->data)->toBeEmpty();
    expect($page->nextCursor)->toBeNull();
});

it('listUsers returns display_name on each row', function () {
    $alice = $this->store->createUser('Alice');
    $bob = $this->store->createUser();
    $page = $this->store->listUsers();
    $byId = [];
    foreach ($page->data as $u) { $byId[$u->id] = $u->displayName; }
    expect($byId[$alice->id])->toBe('Alice');
    expect($byId[$bob->id])->toBeNull();
});

// ───── display_name (ADR 0014) ─────

it('createUser stores display_name when supplied; getUser round-trips it', function () {
    $u = $this->store->createUser('Alice');
    expect($u->displayName)->toBe('Alice');
    expect($this->store->getUser($u->id)->displayName)->toBe('Alice');
});

it('createUser defaults display_name to null', function () {
    $u = $this->store->createUser();
    expect($u->displayName)->toBeNull();
});

it('updateUser sets, leaves untouched, and clears display_name', function () {
    $u = $this->store->createUser('Original');
    $renamed = $this->store->updateUser($u->id, displayName: 'Renamed');
    expect($renamed->displayName)->toBe('Renamed');
    $unchanged = $this->store->updateUser($u->id);
    expect($unchanged->displayName)->toBe('Renamed');
    $cleared = $this->store->updateUser($u->id, displayName: null);
    expect($cleared->displayName)->toBeNull();
});

it('updateUser allows renaming a suspended user', function () {
    $u = $this->store->createUser('Before');
    $this->store->suspendUser($u->id);
    $renamed = $this->store->updateUser($u->id, displayName: 'After');
    expect($renamed->displayName)->toBe('After');
    expect($renamed->status)->toBe(Status::Suspended);
});

it('updateUser on a revoked user raises AlreadyTerminalException', function () {
    $u = $this->store->createUser();
    $this->store->revokeUser($u->id);
    expect(fn() => $this->store->updateUser($u->id, displayName: 'Whatever'))
        ->toThrow(AlreadyTerminalException::class);
});

it('updateUser on unknown user raises NotFoundException', function () {
    expect(fn() => $this->store->updateUser(Id::generate('usr'), displayName: 'ghost'))
        ->toThrow(NotFoundException::class);
});

it('display_name accepts full Unicode without normalization', function () {
    $u = $this->store->createUser('山田 太郎');
    expect($this->store->getUser($u->id)->displayName)->toBe('山田 太郎');
});

// ───── Outer-transaction nesting (ADR 0013) ─────

it('createUser cooperates with an outer transaction (no nested-BEGIN error)', function () {
    $this->pdo->beginTransaction();
    $u = $this->store->createUser();
    expect($this->pdo->inTransaction())->toBeTrue();
    $this->pdo->commit();

    $fetched = $this->store->getUser($u->id);
    expect($fetched->id)->toBe($u->id);
});

it('rolling back an outer transaction undoes the inner createUser + createPasswordCredential', function () {
    $this->pdo->beginTransaction();
    $u = $this->store->createUser();
    $this->store->createPasswordCredential($u->id, 'rolled-back@example.test', 'hunter22-long-enough');
    $this->pdo->rollBack();

    expect(fn() => $this->store->getUser($u->id))->toThrow(NotFoundException::class);
    $countStmt = $this->pdo->query("SELECT count(*) FROM cred WHERE identifier = 'rolled-back@example.test'");
    expect((int) $countStmt->fetchColumn())->toBe(0);
});

it('outer transaction can commit a second SDK call after the first one rolls back its savepoint', function () {
    // Seed an active credential so the next createPasswordCredential with the same identifier collides.
    $seed = $this->store->createUser();
    $this->store->createPasswordCredential($seed->id, 'taken@example.test', 'hunter22-long-enough');

    $this->pdo->beginTransaction();
    $u = $this->store->createUser();
    try {
        $this->store->createPasswordCredential($u->id, 'taken@example.test', 'hunter22-long-enough');
        $this->fail('expected DuplicateCredentialException');
    } catch (DuplicateCredentialException) {
        // expected — savepoint rolled back, outer transaction still live
    }

    // Outer transaction is still usable; another SDK call commits cleanly.
    $cred = $this->store->createPasswordCredential($u->id, 'survivor@example.test', 'hunter22-long-enough');
    $this->pdo->commit();

    expect($this->store->getUser($u->id)->id)->toBe($u->id);
    expect($cred->identifier)->toBe('survivor@example.test');
});

it('multiple SDK calls in one outer transaction commit-or-rollback together', function () {
    $this->pdo->beginTransaction();
    $a = $this->store->createUser();
    $b = $this->store->createUser();
    $this->pdo->rollBack();

    expect(fn() => $this->store->getUser($a->id))->toThrow(NotFoundException::class);
    expect(fn() => $this->store->getUser($b->id))->toThrow(NotFoundException::class);
});

/** RFC 4648 base32 decode (uppercase, ignores padding). */
function base32Decode(string $s): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $stripped = strtoupper(rtrim($s, '='));
    $bits = 0;
    $value = 0;
    $out = '';
    for ($i = 0; $i < strlen($stripped); $i++) {
        $idx = strpos($alphabet, $stripped[$i]);
        if ($idx === false) {
            throw new RuntimeException("invalid base32 char {$stripped[$i]}");
        }
        $value = ($value << 5) | $idx;
        $bits += 5;
        if ($bits >= 8) {
            $out .= chr(($value >> ($bits - 8)) & 0xFF);
            $bits -= 8;
        }
    }
    return $out;
}
