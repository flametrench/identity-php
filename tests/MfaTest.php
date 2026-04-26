<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 MFA primitives. Mirrors
// identity-python/tests/test_mfa.py and Node's mfa.test.ts so any
// drift between SDKs surfaces as a failing test.

declare(strict_types=1);

use Flametrench\Identity\Mfa\RecoveryCodes;
use Flametrench\Identity\Mfa\Totp;
use Flametrench\Identity\Mfa\UserMfaPolicy;

const SECRET_SHA1 = '12345678901234567890';
const SECRET_SHA256 = '12345678901234567890123456789012';
const SECRET_SHA512 = '1234567890123456789012345678901234567890123456789012345678901234';

describe('TOTP RFC 6238 §B vectors — SHA-1', function () {
    foreach (
        [
            [59, '94287082'],
            [1111111109, '07081804'],
            [1111111111, '14050471'],
            [1234567890, '89005924'],
            [2000000000, '69279037'],
            [20000000000, '65353130'],
        ] as [$timestamp, $expected]
    ) {
        it("t={$timestamp} → {$expected}", function () use ($timestamp, $expected) {
            expect(Totp::compute(SECRET_SHA1, $timestamp, digits: 8, algorithm: 'sha1'))
                ->toBe($expected);
        });
    }
});

describe('TOTP RFC 6238 §B vectors — SHA-256', function () {
    foreach (
        [
            [59, '46119246'],
            [1111111109, '68084774'],
            [1111111111, '67062674'],
            [1234567890, '91819424'],
            [2000000000, '90698825'],
            [20000000000, '77737706'],
        ] as [$timestamp, $expected]
    ) {
        it("t={$timestamp} → {$expected}", function () use ($timestamp, $expected) {
            expect(Totp::compute(SECRET_SHA256, $timestamp, digits: 8, algorithm: 'sha256'))
                ->toBe($expected);
        });
    }
});

describe('TOTP RFC 6238 §B vectors — SHA-512', function () {
    foreach (
        [
            [59, '90693936'],
            [1111111109, '25091201'],
            [1111111111, '99943326'],
            [1234567890, '93441116'],
            [2000000000, '38618901'],
            [20000000000, '47863826'],
        ] as [$timestamp, $expected]
    ) {
        it("t={$timestamp} → {$expected}", function () use ($timestamp, $expected) {
            expect(Totp::compute(SECRET_SHA512, $timestamp, digits: 8, algorithm: 'sha512'))
                ->toBe($expected);
        });
    }
});

describe('Totp::verify drift tolerance', function () {
    $ts = 1234567890;

    it('verifies the current window', function () use ($ts) {
        $code = Totp::compute(SECRET_SHA1, $ts);
        expect(Totp::verify(SECRET_SHA1, $code, $ts))->toBeTrue();
    });

    it('verifies one window earlier', function () use ($ts) {
        $prev = Totp::compute(SECRET_SHA1, $ts - Totp::DEFAULT_PERIOD);
        expect(Totp::verify(SECRET_SHA1, $prev, $ts))->toBeTrue();
    });

    it('verifies one window later', function () use ($ts) {
        $next = Totp::compute(SECRET_SHA1, $ts + Totp::DEFAULT_PERIOD);
        expect(Totp::verify(SECRET_SHA1, $next, $ts))->toBeTrue();
    });

    it('rejects two windows earlier with default drift', function () use ($ts) {
        $old = Totp::compute(SECRET_SHA1, $ts - 2 * Totp::DEFAULT_PERIOD);
        expect(Totp::verify(SECRET_SHA1, $old, $ts))->toBeFalse();
    });

    it('rejects garbage input', function () use ($ts) {
        expect(Totp::verify(SECRET_SHA1, 'abc', $ts))->toBeFalse();
        expect(Totp::verify(SECRET_SHA1, '', $ts))->toBeFalse();
        expect(Totp::verify(SECRET_SHA1, '12345', $ts))->toBeFalse();
    });

    it('rejects wrong code', function () use ($ts) {
        expect(Totp::verify(SECRET_SHA1, '000000', $ts))->toBeFalse();
    });
});

describe('Totp::generateSecret', function () {
    it('default length is 20 bytes', function () {
        expect(strlen(Totp::generateSecret()))->toBe(20);
    });

    it('produces unique secrets', function () {
        $set = [];
        for ($i = 0; $i < 50; $i++) {
            $set[bin2hex(Totp::generateSecret())] = true;
        }
        expect(count($set))->toBe(50);
    });
});

describe('Totp::otpauthUri', function () {
    it('contains secret, label, and issuer', function () {
        $uri = Totp::otpauthUri(
            secret: SECRET_SHA1,
            label: 'alice@example.com',
            issuer: 'Flametrench',
        );
        expect($uri)->toStartWith('otpauth://totp/');
        expect($uri)->toContain('Flametrench');
        expect($uri)->toContain('alice%40example.com');
        expect($uri)->toContain('secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    });
});

describe('RecoveryCodes::generate format', function () {
    it('one code matches XXXX-XXXX-XXXX', function () {
        $code = RecoveryCodes::generate();
        expect(strlen($code))->toBe(RecoveryCodes::LENGTH + 2);
        $parts = explode('-', $code);
        expect(count($parts))->toBe(3);
        foreach ($parts as $part) {
            expect(strlen($part))->toBe(4);
        }
    });

    it('excludes ambiguous characters', function () {
        $code = RecoveryCodes::generate();
        foreach (str_split('01OIL') as $ch) {
            expect($code)->not->toContain($ch);
        }
    });

    it('set has 10 codes', function () {
        expect(count(RecoveryCodes::generateSet()))->toBe(RecoveryCodes::COUNT);
    });

    it('set codes are unique', function () {
        $codes = RecoveryCodes::generateSet();
        expect(count(array_unique($codes)))->toBe(RecoveryCodes::COUNT);
    });

    it('normalizeInput uppercases and strips whitespace', function () {
        expect(RecoveryCodes::normalizeInput('  abcd-efgh-jkmn  '))
            ->toBe('ABCD-EFGH-JKMN');
    });

    it('normalizeInput preserves hyphens', function () {
        expect(RecoveryCodes::normalizeInput('abcd-efgh-jkmn'))
            ->toBe('ABCD-EFGH-JKMN');
    });
});

describe('RecoveryCodes::isValid', function () {
    it('accepts canonical form', function () {
        expect(RecoveryCodes::isValid('ABCD-EFGH-JKMN'))->toBeTrue();
    });

    it('rejects ambiguous characters', function () {
        expect(RecoveryCodes::isValid('ABCD-EFGH-JKM0'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCD-EFGH-JKMO'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCD-EFGH-JK1N'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCD-EFGH-JKMI'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCD-EFGH-JKML'))->toBeFalse();
    });

    it('rejects malformed shape', function () {
        expect(RecoveryCodes::isValid('abcd-efgh-jkmn'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCDEFGHJKMN'))->toBeFalse();
        expect(RecoveryCodes::isValid('ABCD-EFGH'))->toBeFalse();
    });
});

describe('UserMfaPolicy::isActiveNow', function () {
    $now = new DateTimeImmutable('2026-04-25T12:00:00Z');

    it('required + no grace → active', function () use ($now) {
        $p = new UserMfaPolicy(
            usrId: 'usr_x',
            required: true,
            graceUntil: null,
            updatedAt: $now,
        );
        expect($p->isActiveNow($now))->toBeTrue();
    });

    it('required + future grace → inactive', function () use ($now) {
        $p = new UserMfaPolicy(
            usrId: 'usr_x',
            required: true,
            graceUntil: new DateTimeImmutable('2026-05-01T00:00:00Z'),
            updatedAt: $now,
        );
        expect($p->isActiveNow($now))->toBeFalse();
    });

    it('required + past grace → active', function () use ($now) {
        $p = new UserMfaPolicy(
            usrId: 'usr_x',
            required: true,
            graceUntil: new DateTimeImmutable('2026-04-01T00:00:00Z'),
            updatedAt: $now,
        );
        expect($p->isActiveNow($now))->toBeTrue();
    });

    it('not required → inactive', function () use ($now) {
        $p = new UserMfaPolicy(
            usrId: 'usr_x',
            required: false,
            graceUntil: null,
            updatedAt: $now,
        );
        expect($p->isActiveNow($now))->toBeFalse();
    });
});
