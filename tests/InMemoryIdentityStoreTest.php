<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Identity\CredentialType;
use Flametrench\Identity\Exceptions\AlreadyTerminalException;
use Flametrench\Identity\Exceptions\CredentialNotActiveException;
use Flametrench\Identity\Exceptions\CredentialTypeMismatchException;
use Flametrench\Identity\Exceptions\DuplicateCredentialException;
use Flametrench\Identity\Exceptions\InvalidCredentialException;
use Flametrench\Identity\Exceptions\InvalidTokenException;
use Flametrench\Identity\Exceptions\NotFoundException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\InMemoryIdentityStore;
use Flametrench\Identity\PasswordCredential;
use Flametrench\Identity\Status;
use Flametrench\Ids\Id;

beforeEach(function () {
    $this->store = new InMemoryIdentityStore();
});

// ─── Users ───

describe('user lifecycle', function () {
    it('creates active users with fresh usr_ ids', function () {
        $u = $this->store->createUser();
        expect($u->id)->toMatch('/^usr_[0-9a-f]{32}$/');
        expect($u->status)->toBe(Status::Active);
    });

    it('throws on unknown user ids', function () {
        expect(fn() => $this->store->getUser('usr_' . str_repeat('0', 32)))
            ->toThrow(NotFoundException::class);
    });

    it('suspendUser cascades to sessions but preserves credentials', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->suspendUser($u->id);
        $afterSession = $this->store->getSession($sw->session->id);
        expect($afterSession->revokedAt)->not->toBeNull();
        $afterCred = $this->store->getCredential($cred->id);
        expect($afterCred->getStatus())->toBe(Status::Active);
    });

    it('revokeUser cascades — sessions terminated AND credentials revoked', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->revokeUser($u->id);
        expect($this->store->getCredential($cred->id)->getStatus())->toBe(Status::Revoked);
        expect($this->store->getSession($sw->session->id)->revokedAt)->not->toBeNull();
    });

    it('rejects double-revoke', function () {
        $u = $this->store->createUser();
        $this->store->revokeUser($u->id);
        expect(fn() => $this->store->revokeUser($u->id))->toThrow(AlreadyTerminalException::class);
    });
});

describe('listUsers (ADR 0015)', function () {
    it('returns all users in id ASC order', function () {
        $a = $this->store->createUser();
        $b = $this->store->createUser();
        $c = $this->store->createUser();
        $page = $this->store->listUsers();
        $ids = array_map(fn($u) => $u->id, $page->data);
        expect($ids)->toEqual([$a->id, $b->id, $c->id]);
        expect($page->nextCursor)->toBeNull();
    });

    it('status filter excludes other states', function () {
        $active = $this->store->createUser();
        $suspended = $this->store->createUser();
        $this->store->suspendUser($suspended->id);
        $ids = array_map(fn($u) => $u->id, $this->store->listUsers(status: \Flametrench\Identity\Status::Active)->data);
        expect($ids)->toEqual([$active->id]);
    });

    it('query is case-insensitive substring against active credential identifiers', function () {
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

    it('cursor walks pages', function () {
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

    it('returns display_name on each row', function () {
        $alice = $this->store->createUser('Alice');
        $bob = $this->store->createUser();
        $page = $this->store->listUsers();
        $byId = [];
        foreach ($page->data as $u) { $byId[$u->id] = $u->displayName; }
        expect($byId[$alice->id])->toBe('Alice');
        expect($byId[$bob->id])->toBeNull();
    });
});

describe('display_name (ADR 0014)', function () {
    it('createUser stores display_name when supplied', function () {
        $u = $this->store->createUser('Alice');
        expect($u->displayName)->toBe('Alice');
        expect($this->store->getUser($u->id)->displayName)->toBe('Alice');
    });

    it('createUser defaults display_name to null', function () {
        $u = $this->store->createUser();
        expect($u->displayName)->toBeNull();
    });

    it('updateUser sets and clears display_name', function () {
        $u = $this->store->createUser('Original');
        $renamed = $this->store->updateUser($u->id, displayName: 'Renamed');
        expect($renamed->displayName)->toBe('Renamed');
        $cleared = $this->store->updateUser($u->id, displayName: null);
        expect($cleared->displayName)->toBeNull();
    });

    it('updateUser with omitted displayName is a no-op (UNSET sentinel)', function () {
        $u = $this->store->createUser('Original');
        $unchanged = $this->store->updateUser($u->id);
        expect($unchanged->displayName)->toBe('Original');
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
});

// ─── Password credentials ───

describe('password credentials', function () {
    it('hashes via Argon2id and exposes a public credential without the hash', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        expect($cred)->toBeInstanceOf(PasswordCredential::class);
        // Ensure no public passwordHash leak.
        $reflection = new ReflectionObject($cred);
        expect($reflection->hasProperty('passwordHash'))->toBeFalse();
    });

    it('rejects duplicate active password credential for same identifier', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        expect(fn() => $this->store->createPasswordCredential($u->id, 'a@x', 'different'))
            ->toThrow(DuplicateCredentialException::class);
    });

    it('verifyPassword succeeds with correct password', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $r = $this->store->verifyPassword('a@x', 'correcthorsebatterystaple');
        expect($r->usrId)->toBe($u->id);
        expect($r->credId)->toBe($cred->id);
    });

    it('verifyPassword fails with wrong password', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        expect(fn() => $this->store->verifyPassword('a@x', 'wrong'))
            ->toThrow(InvalidCredentialException::class);
    });

    it('verifyPassword fails for unknown identifier', function () {
        expect(fn() => $this->store->verifyPassword('nobody@x', 'anything'))
            ->toThrow(InvalidCredentialException::class);
    });

    // ─── ADR 0008: usr_mfa_policy gate on verifyPassword ───

    it('verifyPassword: mfaRequired=false when no policy set', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'pw');
        $r = $this->store->verifyPassword('a@x', 'pw');
        expect($r->mfaRequired)->toBeFalse();
    });

    it('verifyPassword: mfaRequired=true when policy required and no grace', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'pw');
        $this->store->setMfaPolicy($u->id, required: true, graceUntil: null);
        $r = $this->store->verifyPassword('a@x', 'pw');
        expect($r->mfaRequired)->toBeTrue();
    });

    it('verifyPassword: mfaRequired=false during grace window', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'pw');
        $future = (new \DateTimeImmutable())->modify('+7 days');
        $this->store->setMfaPolicy($u->id, required: true, graceUntil: $future);
        $r = $this->store->verifyPassword('a@x', 'pw');
        expect($r->mfaRequired)->toBeFalse();
    });

    it('verifyPassword: mfaRequired=false when policy required=false', function () {
        $u = $this->store->createUser();
        $this->store->createPasswordCredential($u->id, 'a@x', 'pw');
        $this->store->setMfaPolicy($u->id, required: false, graceUntil: null);
        $r = $this->store->verifyPassword('a@x', 'pw');
        expect($r->mfaRequired)->toBeFalse();
    });

    it('rotatePassword revokes old, issues new with replaces, and cascades sessions', function () {
        $u = $this->store->createUser();
        $oldCred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $sw = $this->store->createSession($u->id, $oldCred->id, 3600);
        $newCred = $this->store->rotatePassword($oldCred->id, 'NEW-correcthorsebatterystaple');
        expect($newCred->replaces)->toBe($oldCred->id);
        expect($this->store->getCredential($oldCred->id)->getStatus())->toBe(Status::Revoked);
        expect($this->store->getSession($sw->session->id)->revokedAt)->not->toBeNull();
        expect(fn() => $this->store->verifyPassword('a@x', 'correcthorsebatterystaple'))
            ->toThrow(InvalidCredentialException::class);
        $r = $this->store->verifyPassword('a@x', 'NEW-correcthorsebatterystaple');
        expect($r->credId)->toBe($newCred->id);
    });

    it('rotatePassword on a non-password credential is a type mismatch', function () {
        $u = $this->store->createUser();
        $oidc = $this->store->createOidcCredential($u->id, 'a@x', 'https://i', 'sub');
        expect(fn() => $this->store->rotatePassword($oidc->id, 'whatever'))
            ->toThrow(CredentialTypeMismatchException::class);
    });
});

// ─── Passkey + OIDC ───

describe('non-password credentials', function () {
    it('creates and retrieves a passkey credential', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasskeyCredential($u->id, 'credIdB64', "\xa5\x01\x02\x03", 0, 'example.com');
        expect($cred->passkeyRpId)->toBe('example.com');
        expect($cred->passkeySignCount)->toBe(0);
        $reflection = new ReflectionObject($cred);
        expect($reflection->hasProperty('passkeyPublicKey'))->toBeFalse();
    });

    it('creates and retrieves an OIDC credential', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createOidcCredential($u->id, 'a@x', 'https://accounts.google.com', '1234567890');
        expect($cred->oidcIssuer)->toBe('https://accounts.google.com');
        expect($cred->oidcSubject)->toBe('1234567890');
    });
});

// ─── Credential lifecycle ───

describe('credential lifecycle', function () {
    it('suspend removes from active-identifier index and cascades sessions', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->suspendCredential($cred->id);
        expect($this->store->getSession($sw->session->id)->revokedAt)->not->toBeNull();
        expect($this->store->findCredentialByIdentifier(CredentialType::Password, 'a@x'))->toBeNull();
    });

    it('reinstate refuses when another active cred owns the identifier', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'first');
        $this->store->suspendCredential($cred->id);
        $this->store->createPasswordCredential($u->id, 'a@x', 'second');
        expect(fn() => $this->store->reinstateCredential($cred->id))
            ->toThrow(DuplicateCredentialException::class);
    });

    it('revoke cascades session termination', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->revokeCredential($cred->id);
        expect($this->store->getSession($sw->session->id)->revokedAt)->not->toBeNull();
    });
});

// ─── findCredentialByIdentifier ───

describe('findCredentialByIdentifier', function () {
    it('returns the active credential', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $found = $this->store->findCredentialByIdentifier(CredentialType::Password, 'a@x');
        expect($found?->getId())->toBe($cred->id);
    });

    it('returns null for unknown identifier', function () {
        expect($this->store->findCredentialByIdentifier(CredentialType::Password, 'nobody@x'))
            ->toBeNull();
    });

    it('skips revoked credentials', function () {
        $u = $this->store->createUser();
        $cred = $this->store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        $this->store->revokeCredential($cred->id);
        expect($this->store->findCredentialByIdentifier(CredentialType::Password, 'a@x'))
            ->toBeNull();
    });
});

// ─── Sessions ───

describe('sessions', function () {
    function setup(InMemoryIdentityStore $store): array {
        $u = $store->createUser();
        $cred = $store->createPasswordCredential($u->id, 'a@x', 'correcthorsebatterystaple');
        return [$u, $cred];
    }

    it('createSession returns an opaque token distinct from session id', function () {
        [$u, $cred] = setup($this->store);
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        expect($sw->session->id)->toMatch('/^ses_[0-9a-f]{32}$/');
        expect($sw->token)->not->toBe($sw->session->id);
        expect(strlen($sw->token))->toBeGreaterThan(32);
    });

    it('verifySessionToken accepts a fresh token', function () {
        [$u, $cred] = setup($this->store);
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $verified = $this->store->verifySessionToken($sw->token);
        expect($verified->id)->toBe($sw->session->id);
    });

    it('verifySessionToken rejects unknown token', function () {
        expect(fn() => $this->store->verifySessionToken('not-a-real-token'))
            ->toThrow(InvalidTokenException::class);
    });

    it('verifySessionToken rejects revoked-session token', function () {
        [$u, $cred] = setup($this->store);
        $sw = $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->revokeSession($sw->session->id);
        expect(fn() => $this->store->verifySessionToken($sw->token))
            ->toThrow(InvalidTokenException::class);
    });

    it('refreshSession rotates: new id, new token, old revoked', function () {
        [$u, $cred] = setup($this->store);
        $first = $this->store->createSession($u->id, $cred->id, 3600);
        $refreshed = $this->store->refreshSession($first->session->id);
        expect($refreshed->session->id)->not->toBe($first->session->id);
        expect($refreshed->token)->not->toBe($first->token);
        expect($this->store->getSession($first->session->id)->revokedAt)->not->toBeNull();
        expect(fn() => $this->store->verifySessionToken($first->token))
            ->toThrow(InvalidTokenException::class);
        expect($this->store->verifySessionToken($refreshed->token)->id)->toBe($refreshed->session->id);
    });

    it('createSession rejects ttl < 60', function () {
        [$u, $cred] = setup($this->store);
        expect(fn() => $this->store->createSession($u->id, $cred->id, 5))
            ->toThrow(PreconditionException::class);
    });

    it('createSession rejects suspended credential', function () {
        [$u, $cred] = setup($this->store);
        $this->store->suspendCredential($cred->id);
        expect(fn() => $this->store->createSession($u->id, $cred->id, 3600))
            ->toThrow(CredentialNotActiveException::class);
    });

    it('listSessionsForUser returns the user\'s sessions', function () {
        [$u, $cred] = setup($this->store);
        $this->store->createSession($u->id, $cred->id, 3600);
        $this->store->createSession($u->id, $cred->id, 3600);
        $page = $this->store->listSessionsForUser($u->id);
        expect(count($page->data))->toBe(2);
        foreach ($page->data as $s) expect($s->usrId)->toBe($u->id);
    });
});
