<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Identity\Exceptions\AlreadyTerminalException;
use Flametrench\Identity\Exceptions\InvalidPatTokenException;
use Flametrench\Identity\Exceptions\NotFoundException;
use Flametrench\Identity\Exceptions\PatExpiredException;
use Flametrench\Identity\Exceptions\PatRevokedException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\InMemoryIdentityStore;
use Flametrench\Identity\Pat\PatStatus;

// All PAT tests use a controllable clock so we can exercise the
// expiry and last_used_at coalescing windows deterministically.
function makeStore(\DateTimeImmutable &$clock, int $coalesceSeconds = 0): InMemoryIdentityStore
{
    return new InMemoryIdentityStore(
        clock: function () use (&$clock) { return $clock; },
        patLastUsedCoalesceSeconds: $coalesceSeconds,
    );
}

describe('createPat', function () {
    it('returns a wire-format token and a PersonalAccessToken record', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $result = $store->createPat($u->id, name: 'laptop-cli', scope: ['repo:read']);

        expect($result['pat']->id)->toMatch('/^pat_[0-9a-f]{32}$/');
        expect($result['pat']->name)->toBe('laptop-cli');
        expect($result['pat']->scope)->toBe(['repo:read']);
        expect($result['pat']->status)->toBe(PatStatus::Active);
        expect($result['pat']->lastUsedAt)->toBeNull();
        expect($result['pat']->expiresAt)->toBeNull();
        expect($result['token'])->toMatch('/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/');
        // The id segment in the token MUST match the row's id.
        expect(substr($result['token'], 4, 32))->toBe(substr($result['pat']->id, 4));
    });

    it('rejects a name shorter than 1 char', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $store->createPat($u->id, name: '', scope: []);
    })->throws(PreconditionException::class);

    it('rejects a name longer than 120 chars', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $store->createPat($u->id, name: str_repeat('x', 121), scope: []);
    })->throws(PreconditionException::class);

    it('rejects an expires_at in the past', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $store->createPat($u->id, name: 'laptop', scope: [], expiresAt: new \DateTimeImmutable('2026-04-01T00:00:00Z'));
    })->throws(PreconditionException::class);

    // security-audit-v0.3.md H1: ADR 0016 §"Constraints" caps expires_at at
    // 365 days from creation. Pre-fix this was unenforced — adopters could
    // mint century-long PATs.
    it('accepts an expires_at exactly 365 days out (cap inclusive)', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $exp = $clock->modify('+365 days');
        $r = $store->createPat($u->id, name: 'laptop', scope: [], expiresAt: $exp);
        expect($r['pat']->expiresAt->format('c'))->toBe($exp->format('c'));
    });

    it('rejects an expires_at beyond the 365-day cap', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $exp = $clock->modify('+365 days +1 second');
        $store->createPat($u->id, name: 'laptop', scope: [], expiresAt: $exp);
    })->throws(PreconditionException::class);

    it('refuses to issue PATs for revoked users', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $store->revokeUser($u->id);
        $store->createPat($u->id, name: 'laptop', scope: []);
    })->throws(AlreadyTerminalException::class);
});

describe('verifyPatToken — happy path', function () {
    it('returns VerifiedPat with usr_id and scope on a fresh token', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: ['admin']);

        $verified = $store->verifyPatToken($r['token']);

        expect($verified->patId)->toBe($r['pat']->id);
        expect($verified->usrId)->toBe($u->id);
        expect($verified->scope)->toBe(['admin']);
    });

    it('updates last_used_at on first verify', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock); // coalesce=0 → always update
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);
        expect($r['pat']->lastUsedAt)->toBeNull();

        $clock = $clock->modify('+5 seconds');
        $store->verifyPatToken($r['token']);
        $reread = $store->getPat($r['pat']->id);
        expect($reread->lastUsedAt?->format('c'))->toBe($clock->format('c'));
    });
});

describe('verifyPatToken — error ordering (ADR 0016 §"Verification semantics")', function () {
    it('throws InvalidPatTokenException for malformed bearer', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $store->verifyPatToken('not-a-pat-token');
    })->throws(InvalidPatTokenException::class);

    it('throws InvalidPatTokenException for non-pat prefix', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $store->verifyPatToken('shr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_secretvalue');
    })->throws(InvalidPatTokenException::class);

    it('throws InvalidPatTokenException for missing row (token-presence oracle defense)', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        // 32 valid hex chars + a fake secret — passes structural checks
        // but the row does not exist.
        $store->verifyPatToken('pat_' . str_repeat('a', 32) . '_anysecret');
    })->throws(InvalidPatTokenException::class);

    it('throws InvalidPatTokenException for wrong secret (same shape as missing-row)', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);
        $idHex = substr($r['pat']->id, 4);
        $store->verifyPatToken("pat_{$idHex}_definitelyWrongSecret");
    })->throws(InvalidPatTokenException::class);

    it('throws PatRevokedException for revoked tokens (ordered before expiry/secret checks)', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: [], expiresAt: new \DateTimeImmutable('2026-06-01T00:00:00Z'));
        $store->revokePat($r['pat']->id);
        // Even with a valid secret, revoke wins.
        $store->verifyPatToken($r['token']);
    })->throws(PatRevokedException::class);

    it('throws PatExpiredException for past-expiry tokens (ordered before secret check)', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: [], expiresAt: new \DateTimeImmutable('2026-05-01T13:00:00Z'));
        $clock = new \DateTimeImmutable('2026-05-02T00:00:00Z');
        $store->verifyPatToken($r['token']);
    })->throws(PatExpiredException::class);
});

describe('revokePat', function () {
    it('marks the row revoked and updates the public status', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);
        $revoked = $store->revokePat($r['pat']->id);

        expect($revoked->status)->toBe(PatStatus::Revoked);
        expect($revoked->revokedAt?->format('c'))->toBe($clock->format('c'));
    });

    it('is idempotent — revoking an already-revoked PAT returns the existing row', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);
        $first = $store->revokePat($r['pat']->id);

        $clock = $clock->modify('+1 hour');
        $second = $store->revokePat($r['pat']->id);

        expect($second->revokedAt?->format('c'))->toBe($first->revokedAt?->format('c'));
    });

    it('throws NotFoundException for an unknown patId', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $store->revokePat('pat_' . str_repeat('a', 32));
    })->throws(NotFoundException::class);
});

describe('listPatsForUser', function () {
    it('returns id-ordered PATs scoped to the user', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $alice = $store->createUser();
        $bob = $store->createUser();
        $a1 = $store->createPat($alice->id, name: 'a-1', scope: []);
        usleep(2000);
        $a2 = $store->createPat($alice->id, name: 'a-2', scope: []);
        $store->createPat($bob->id, name: 'bob-1', scope: []);

        $page = $store->listPatsForUser($alice->id);

        expect(count($page->data))->toBe(2);
        expect($page->data[0]->id)->toBe($a1['pat']->id);
        expect($page->data[1]->id)->toBe($a2['pat']->id);
        expect($page->nextCursor)->toBeNull();
    });

    it('filters by status', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $live = $store->createPat($u->id, name: 'live', scope: []);
        $rev = $store->createPat($u->id, name: 'rev', scope: []);
        $store->revokePat($rev['pat']->id);

        $activeOnly = $store->listPatsForUser($u->id, status: PatStatus::Active);
        expect(count($activeOnly->data))->toBe(1);
        expect($activeOnly->data[0]->id)->toBe($live['pat']->id);

        $revokedOnly = $store->listPatsForUser($u->id, status: PatStatus::Revoked);
        expect(count($revokedOnly->data))->toBe(1);
        expect($revokedOnly->data[0]->id)->toBe($rev['pat']->id);
    });

    it('paginates with cursor', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock);
        $u = $store->createUser();
        $ids = [];
        for ($i = 0; $i < 5; $i++) {
            usleep(2000);
            $ids[] = $store->createPat($u->id, name: "p{$i}", scope: [])['pat']->id;
        }
        sort($ids);

        $first = $store->listPatsForUser($u->id, limit: 2);
        expect(count($first->data))->toBe(2);
        expect($first->nextCursor)->not->toBeNull();

        $second = $store->listPatsForUser($u->id, cursor: $first->nextCursor, limit: 2);
        expect(count($second->data))->toBe(2);
        expect($second->data[0]->id)->toBe($ids[2]);
    });
});

describe('last_used_at coalescing (ADR 0016 §"Operational notes")', function () {
    it('does NOT update last_used_at within the coalescing window', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock, coalesceSeconds: 60);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);

        $clock = $clock->modify('+5 seconds');
        $store->verifyPatToken($r['token']);
        $afterFirst = $store->getPat($r['pat']->id)->lastUsedAt;

        $clock = $clock->modify('+10 seconds'); // 15s in — well within 60s window
        $store->verifyPatToken($r['token']);
        $afterSecond = $store->getPat($r['pat']->id)->lastUsedAt;

        expect($afterSecond?->format('c'))->toBe($afterFirst?->format('c'));
    });

    it('updates last_used_at after the coalescing window expires', function () {
        $clock = new \DateTimeImmutable('2026-05-01T12:00:00Z');
        $store = makeStore($clock, coalesceSeconds: 60);
        $u = $store->createUser();
        $r = $store->createPat($u->id, name: 'cli', scope: []);

        $clock = $clock->modify('+5 seconds');
        $store->verifyPatToken($r['token']);
        $afterFirst = $store->getPat($r['pat']->id)->lastUsedAt;

        $clock = $clock->modify('+90 seconds'); // 95s in — past 60s window
        $store->verifyPatToken($r['token']);
        $afterSecond = $store->getPat($r['pat']->id)->lastUsedAt;

        expect($afterSecond?->format('c'))->not->toBe($afterFirst?->format('c'));
        expect($afterSecond?->format('c'))->toBe($clock->format('c'));
    });
});
