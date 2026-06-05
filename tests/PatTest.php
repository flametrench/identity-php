<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Identity\AuthKind;
use Flametrench\Identity\Exceptions\InvalidPatTokenException;
use Flametrench\Identity\Exceptions\NotFoundException;
use Flametrench\Identity\Exceptions\PatExpiredException;
use Flametrench\Identity\Exceptions\PatRevokedException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\InMemoryIdentityStore;
use Flametrench\Identity\Pat;
use Flametrench\Identity\PatStatus;

describe('Pat::isStructurallyValid', function () {
    $valid = [
        'pat_0190f2a81b3c7abc8123456789abcdef_x',
        'pat_0190f2a81b3c7abc8123456789abcdef_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_aBcDe',
        'pat_ffffffffffffffffffffffffffffffff_kJ8XVqW3pYf7N2bL9Q-D5FxR8aTcM1eZ',
    ];
    $invalid = [
        '',
        'shr_0190f2a81b3c7abc8123456789abcdef_someSecretValue',
        '0190f2a81b3c7abc8123456789abcdef_someSecretValue',
        'pat_0190F2A81B3C7ABC8123456789ABCDEF_secret',
        'pat_0190f2a81b3c_secret',
        'pat_0190f2a81b3c7abc8123456789abcdef00_secret',
        'pat_0190f2a81b3c7abc8123456789abcdefxsecret',
        'pat_0190f2a81b3c7abc8123456789abcdef_',
        'pat_g190f2a81b3c7abc8123456789abcdef_secret',
    ];

    foreach ($valid as $t) {
        it("accepts: {$t}", fn() => expect(Pat::isStructurallyValid($t))->toBeTrue());
    }
    foreach ($invalid as $t) {
        it("rejects: {$t}", fn() => expect(Pat::isStructurallyValid($t))->toBeFalse());
    }
});

describe('Pat::classifyBearer', function () {
    it('classifies pat_ prefix as pat', function () {
        expect(Pat::classifyBearer('pat_0190f2a81b3c7abc8123456789abcdef_secretSegmentHere'))
            ->toBe(AuthKind::Pat);
    });

    it('classifies shr_ prefix as share', function () {
        expect(Pat::classifyBearer('shr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_someShareSecret'))
            ->toBe(AuthKind::Share);
    });

    it('classifies opaque session token as session', function () {
        expect(Pat::classifyBearer('G7Pc1xqVz4nN8mYf2tWbE3kLjRsT5vUaB6cD9eFgHiJk'))
            ->toBe(AuthKind::Session);
    });

    it('classifies JWT-shaped token as session', function () {
        expect(Pat::classifyBearer('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signaturepart'))
            ->toBe(AuthKind::Session);
    });

    it('classifies malformed pat_ token as pat (no cross-routing)', function () {
        expect(Pat::classifyBearer('pat_0190f2a81b3c7abc8123456789abcdef'))
            ->toBe(AuthKind::Pat);
    });

    it('classifies malformed shr_ token as share (no cross-routing)', function () {
        expect(Pat::classifyBearer('shr_garbage'))
            ->toBe(AuthKind::Share);
    });
});

describe('InMemoryIdentityStore PAT operations', function () {
    beforeEach(function () {
        $this->store = new InMemoryIdentityStore();
        $this->user = $this->store->createUser('Test User');
    });

    it('createPat returns a token and pat record', function () {
        $result = $this->store->createPat($this->user->id, 'My CLI', ['cloud:read']);
        expect($result->pat->id)->toMatch('/^pat_[0-9a-f]{32}$/');
        expect($result->pat->name)->toBe('My CLI');
        expect($result->pat->scope)->toBe(['cloud:read']);
        expect($result->pat->status)->toBe(PatStatus::Active);
        expect($result->pat->revokedAt)->toBeNull();
        expect($result->token)->toMatch('/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/');
    });

    it('verifyPatToken succeeds and updates last_used_at', function () {
        $result = $this->store->createPat($this->user->id, 'Test', ['read']);
        $verified = $this->store->verifyPatToken($result->token);
        expect($verified->patId)->toBe($result->pat->id);
        expect($verified->usrId)->toBe($this->user->id);
        expect($verified->scope)->toBe(['read']);

        $pat = $this->store->getPat($result->pat->id);
        expect($pat->lastUsedAt)->not->toBeNull();
    });

    it('verifyPatToken throws InvalidPatTokenException on wrong secret', function () {
        $result = $this->store->createPat($this->user->id, 'Test', []);
        $parts = explode('_', $result->token, 3);
        $badToken = $parts[0] . '_' . $parts[1] . '_' . str_repeat('x', strlen($parts[2]));
        expect(fn() => $this->store->verifyPatToken($badToken))
            ->toThrow(InvalidPatTokenException::class);
    });

    it('verifyPatToken throws InvalidPatTokenException on structural failure', function () {
        expect(fn() => $this->store->verifyPatToken('not-a-pat'))
            ->toThrow(InvalidPatTokenException::class);
    });

    it('verifyPatToken throws PatRevokedException after revoke', function () {
        $result = $this->store->createPat($this->user->id, 'Test', []);
        $this->store->revokePat($result->pat->id);
        expect(fn() => $this->store->verifyPatToken($result->token))
            ->toThrow(PatRevokedException::class);
    });

    it('verifyPatToken throws PatExpiredException on expired PAT', function () {
        $time = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $store = new InMemoryIdentityStore(function () use (&$time) { return $time; });
        $user = $store->createUser();
        $expiresAt = $time->modify('+1 second');
        $r = $store->createPat($user->id, 'Expiring', [], $expiresAt);
        $time = $expiresAt->modify('+1 second'); // advance clock past expiry
        expect(fn() => $store->verifyPatToken($r->token))
            ->toThrow(PatExpiredException::class);
    });

    it('revokePat sets revoked_at and returns revoked status', function () {
        $result = $this->store->createPat($this->user->id, 'Test', []);
        $revoked = $this->store->revokePat($result->pat->id);
        expect($revoked->status)->toBe(PatStatus::Revoked);
        expect($revoked->revokedAt)->not->toBeNull();
    });

    it('listPatsForUser returns owned PATs', function () {
        $this->store->createPat($this->user->id, 'PAT 1', []);
        $this->store->createPat($this->user->id, 'PAT 2', []);
        $page = $this->store->listPatsForUser($this->user->id);
        expect(count($page->data))->toBe(2);
    });

    it('getPat throws NotFoundException for unknown id', function () {
        expect(fn() => $this->store->getPat('pat_' . str_repeat('0', 32)))
            ->toThrow(NotFoundException::class);
    });

    it('revokeUser cascades to PATs', function () {
        $result = $this->store->createPat($this->user->id, 'Test', []);
        $this->store->revokeUser($this->user->id);
        $pat = $this->store->getPat($result->pat->id);
        expect($pat->status)->toBe(PatStatus::Revoked);
        expect($pat->revokedAt)->not->toBeNull();
    });

    it('createPat rejects name longer than 120 code units', function () {
        expect(fn() => $this->store->createPat($this->user->id, str_repeat('a', 121), []))
            ->toThrow(PreconditionException::class);
    });

    it('createPat accepts name of exactly 120 code units', function () {
        $result = $this->store->createPat($this->user->id, str_repeat('a', 120), []);
        expect($result->pat->name)->toBe(str_repeat('a', 120));
    });

    it('createPat rejects expires_at beyond 365 days', function () {
        $tooFar = (new DateTimeImmutable())->modify('+366 days');
        expect(fn() => $this->store->createPat($this->user->id, 'Test', [], $tooFar))
            ->toThrow(PreconditionException::class);
    });

    it('createPat with empty scope is valid', function () {
        $result = $this->store->createPat($this->user->id, 'No scope', []);
        expect($result->pat->scope)->toBe([]);
    });
});
