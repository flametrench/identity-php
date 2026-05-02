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
use Flametrench\Identity\Pat\PatStatus;
use Flametrench\Identity\PostgresIdentityStore;

$identityPostgresUrl = getenv('IDENTITY_POSTGRES_URL') ?: null;

if ($identityPostgresUrl === null) {
    fwrite(STDERR, "[PostgresPatTest] IDENTITY_POSTGRES_URL not set; tests skipped.\n");
    return;
}

beforeEach(function () use ($identityPostgresUrl) {
    $pdo = identityPgPdoFromUrl($identityPostgresUrl);
    $this->pdo = $pdo;
    $pdo->exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    $pdo->exec((string) file_get_contents(__DIR__ . '/postgres-schema.sql'));

    $clockState = new \stdClass();
    $clockState->now = new \DateTimeImmutable('2026-05-01T12:00:00Z');
    $this->clockState = $clockState;
    $clock = function () use ($clockState) { return $clockState->now; };

    // coalesce=0 in default test store so most assertions don't fight
    // the 60s window. Coalescing-specific tests instantiate their own.
    $this->store = new PostgresIdentityStore(
        pdo: $pdo,
        clock: $clock,
        patLastUsedCoalesceSeconds: 0,
    );
});

function advanceClock(\stdClass $state, string $modifier): void
{
    $state->now = $state->now->modify($modifier);
}

it('createPat persists a row and returns wire-format token', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat($u->id, name: 'laptop-cli', scope: ['repo:read']);

    expect($r['pat']->id)->toMatch('/^pat_[0-9a-f]{32}$/');
    expect($r['pat']->name)->toBe('laptop-cli');
    expect($r['pat']->scope)->toBe(['repo:read']);
    expect($r['pat']->status)->toBe(PatStatus::Active);
    expect($r['token'])->toMatch('/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/');
    expect(substr($r['token'], 4, 32))->toBe(substr($r['pat']->id, 4));
});

it('createPat rejects revoked users with AlreadyTerminalException', function () {
    $u = $this->store->createUser();
    $this->store->revokeUser($u->id);
    $this->store->createPat($u->id, name: 'cli', scope: []);
})->throws(AlreadyTerminalException::class);

it('createPat rejects expires_at in the past with PreconditionException', function () {
    $u = $this->store->createUser();
    $this->store->createPat(
        $u->id,
        name: 'cli',
        scope: [],
        expiresAt: new \DateTimeImmutable('2026-04-01T00:00:00Z'),
    );
})->throws(PreconditionException::class);

it('verifyPatToken returns VerifiedPat with usr_id and scope', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat($u->id, name: 'cli', scope: ['admin']);
    $verified = $this->store->verifyPatToken($r['token']);

    expect($verified->patId)->toBe($r['pat']->id);
    expect($verified->usrId)->toBe($u->id);
    expect($verified->scope)->toBe(['admin']);
});

it('verifyPatToken updates last_used_at when coalescing disabled', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat($u->id, name: 'cli', scope: []);
    expect($r['pat']->lastUsedAt)->toBeNull();

    advanceClock($this->clockState, '+5 seconds');
    $this->store->verifyPatToken($r['token']);
    $reread = $this->store->getPat($r['pat']->id);
    expect($reread->lastUsedAt?->format('c'))->toBe($this->clockState->now->format('c'));
});

it('verifyPatToken throws InvalidPatTokenException for missing row (timing oracle defense)', function () {
    $this->store->verifyPatToken('pat_' . str_repeat('a', 32) . '_anysecret');
})->throws(InvalidPatTokenException::class);

it('verifyPatToken throws InvalidPatTokenException for wrong secret', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat($u->id, name: 'cli', scope: []);
    $idHex = substr($r['pat']->id, 4);
    $this->store->verifyPatToken("pat_{$idHex}_wrongSecret");
})->throws(InvalidPatTokenException::class);

it('verifyPatToken throws PatRevokedException for revoked tokens (ordered first)', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat(
        $u->id,
        name: 'cli',
        scope: [],
        expiresAt: new \DateTimeImmutable('2026-06-01T00:00:00Z'),
    );
    $this->store->revokePat($r['pat']->id);
    $this->store->verifyPatToken($r['token']);
})->throws(PatRevokedException::class);

it('verifyPatToken throws PatExpiredException after expires_at', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat(
        $u->id,
        name: 'cli',
        scope: [],
        expiresAt: new \DateTimeImmutable('2026-05-01T13:00:00Z'),
    );
    advanceClock($this->clockState, '+1 day');
    $this->store->verifyPatToken($r['token']);
})->throws(PatExpiredException::class);

it('revokePat is idempotent', function () {
    $u = $this->store->createUser();
    $r = $this->store->createPat($u->id, name: 'cli', scope: []);
    $first = $this->store->revokePat($r['pat']->id);

    advanceClock($this->clockState, '+1 hour');
    $second = $this->store->revokePat($r['pat']->id);

    expect($second->revokedAt?->format('c'))->toBe($first->revokedAt?->format('c'));
});

it('revokePat throws NotFoundException for unknown patId', function () {
    // Use Id::generate('pat') so the id is structurally valid (UUIDv7);
    // the row simply doesn't exist. Bare-hex stand-ins fail UUID
    // validation upstream, which is a different error class.
    $this->store->revokePat(\Flametrench\Ids\Id::generate('pat'));
})->throws(NotFoundException::class);

it('listPatsForUser returns id-ordered PATs scoped to the user', function () {
    $alice = $this->store->createUser();
    $bob = $this->store->createUser();
    $this->store->createPat($alice->id, name: 'a-1', scope: []);
    usleep(2000);
    $this->store->createPat($alice->id, name: 'a-2', scope: []);
    $this->store->createPat($bob->id, name: 'bob-1', scope: []);

    $page = $this->store->listPatsForUser($alice->id);
    expect(count($page->data))->toBe(2);
    expect($page->data[0]->name)->toBe('a-1');
    expect($page->data[1]->name)->toBe('a-2');
});

it('listPatsForUser filters by status', function () {
    $u = $this->store->createUser();
    $live = $this->store->createPat($u->id, name: 'live', scope: []);
    $rev = $this->store->createPat($u->id, name: 'rev', scope: []);
    $this->store->revokePat($rev['pat']->id);

    $activeOnly = $this->store->listPatsForUser($u->id, status: PatStatus::Active);
    expect(count($activeOnly->data))->toBe(1);
    expect($activeOnly->data[0]->id)->toBe($live['pat']->id);

    $revokedOnly = $this->store->listPatsForUser($u->id, status: PatStatus::Revoked);
    expect(count($revokedOnly->data))->toBe(1);
    expect($revokedOnly->data[0]->id)->toBe($rev['pat']->id);
});

it('listPatsForUser paginates with cursor', function () {
    $u = $this->store->createUser();
    $ids = [];
    for ($i = 0; $i < 5; $i++) {
        usleep(2000);
        $ids[] = $this->store->createPat($u->id, name: "p{$i}", scope: [])['pat']->id;
    }
    sort($ids);

    $first = $this->store->listPatsForUser($u->id, limit: 2);
    expect(count($first->data))->toBe(2);
    expect($first->nextCursor)->not->toBeNull();

    $second = $this->store->listPatsForUser($u->id, cursor: $first->nextCursor, limit: 2);
    expect(count($second->data))->toBe(2);
    expect($second->data[0]->id)->toBe($ids[2]);
});

it('coalesces last_used_at writes within the configured window', function () use ($identityPostgresUrl) {
    $clockState = new \stdClass();
    $clockState->now = new \DateTimeImmutable('2026-05-01T12:00:00Z');
    $clock = function () use ($clockState) { return $clockState->now; };
    $store = new PostgresIdentityStore(
        pdo: $this->pdo,
        clock: $clock,
        patLastUsedCoalesceSeconds: 60,
    );

    $u = $store->createUser();
    $r = $store->createPat($u->id, name: 'cli', scope: []);

    advanceClock($clockState, '+5 seconds');
    $store->verifyPatToken($r['token']);
    $afterFirst = $store->getPat($r['pat']->id)->lastUsedAt;

    advanceClock($clockState, '+10 seconds'); // 15s in — within 60s window
    $store->verifyPatToken($r['token']);
    $afterSecond = $store->getPat($r['pat']->id)->lastUsedAt;

    expect($afterSecond?->format('c'))->toBe($afterFirst?->format('c'));

    advanceClock($clockState, '+90 seconds'); // 105s past first verify — past window
    $store->verifyPatToken($r['token']);
    $afterThird = $store->getPat($r['pat']->id)->lastUsedAt;

    expect($afterThird?->format('c'))->not->toBe($afterFirst?->format('c'));
});

it('cooperates with an outer transaction via SAVEPOINT (ADR 0013)', function () {
    $u = $this->store->createUser();
    $this->pdo->beginTransaction();
    try {
        $r = $this->store->createPat($u->id, name: 'cli', scope: []);
        $this->store->revokePat($r['pat']->id);
        $this->pdo->commit();
        $reread = $this->store->getPat($r['pat']->id);
        expect($reread->status)->toBe(PatStatus::Revoked);
    } catch (\Throwable $e) {
        if ($this->pdo->inTransaction()) $this->pdo->rollBack();
        throw $e;
    }
});

it('rolls back the savepoint on inner failure without aborting the outer transaction', function () {
    $u = $this->store->createUser();
    $this->pdo->beginTransaction();
    try {
        // Issue one PAT successfully...
        $good = $this->store->createPat($u->id, name: 'good', scope: []);
        // ...then provoke a failure (revoked user) inside the same outer txn.
        $other = $this->store->createUser();
        $this->store->revokeUser($other->id);
        try {
            $this->store->createPat($other->id, name: 'doomed', scope: []);
            $this->fail('expected AlreadyTerminalException');
        } catch (AlreadyTerminalException) {
            // Expected — savepoint should have rolled back without aborting outer.
        }
        // Still in outer txn, can keep working.
        $r2 = $this->store->createPat($u->id, name: 'after-failure', scope: []);
        $this->pdo->commit();

        $page = $this->store->listPatsForUser($u->id);
        expect(count($page->data))->toBe(2);
    } catch (\Throwable $e) {
        if ($this->pdo->inTransaction()) $this->pdo->rollBack();
        throw $e;
    }
});
