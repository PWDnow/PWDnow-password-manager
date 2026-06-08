// rateLimiter unit tests — runs with an InMemoryStateStore wired into ctx.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryStateStore } from '../lib/stateStore.js';
import { ctx } from '../lib/context.js';

before(() => { ctx.stateStore = new InMemoryStateStore(); });

const {
  checkLoginRate, LOGIN_MAX_PER_WINDOW,
  checkHintsRate, HINTS_MAX_PER_WINDOW,
  checkAccountRate, recordAccountFailure, resetAccountFailures,
  checkFingerprintRate, recordFingerprintFailure, resetFingerprintFailures,
  checkRegisterRate, REGISTER_MAX_PER_WINDOW,
  checkEmergencyRate, EMERGENCY_MAX_PER_WINDOW,
} = await import('../lib/rateLimiter.js');

describe('rateLimiter — login rate', () => {
  it(`allows first ${LOGIN_MAX_PER_WINDOW} requests`, async () => {
    const ip = `login-${Math.random()}`;
    for (let i = 0; i < LOGIN_MAX_PER_WINDOW; i++) {
      assert.ok(await checkLoginRate(ip), `attempt ${i + 1} should be allowed`);
    }
  });

  it('blocks once limit is exceeded', async () => {
    const ip = `login-${Math.random()}`;
    for (let i = 0; i < LOGIN_MAX_PER_WINDOW; i++) await checkLoginRate(ip);
    assert.ok(!(await checkLoginRate(ip)), 'over-limit should be blocked');
  });

  it('different IPs are independent', async () => {
    const ip1 = `login-${Math.random()}`;
    const ip2 = `login-${Math.random()}`;
    for (let i = 0; i < LOGIN_MAX_PER_WINDOW; i++) await checkLoginRate(ip1);
    assert.ok(!(await checkLoginRate(ip1)));
    assert.ok(await checkLoginRate(ip2), 'unrelated IP should still be allowed');
  });
});

describe('rateLimiter — account lockout', () => {
  it('allows when no failures recorded', async () => {
    const eh = `eh-${Math.random()}`;
    assert.ok(await checkAccountRate(eh));
  });

  it('still allows before the lockout threshold (4 failures)', async () => {
    const eh = `eh-${Math.random()}`;
    for (let i = 0; i < 4; i++) await recordAccountFailure(eh);
    assert.ok(await checkAccountRate(eh), '4 failures should not yet lock (schedule[4]=0)');
  });

  it('locks after 5 failures (ACCOUNT_LOCKOUT_SCHEDULE_MS[5] = 30000ms)', async () => {
    const eh = `eh-${Math.random()}`;
    for (let i = 0; i < 5; i++) await recordAccountFailure(eh);
    assert.ok(!(await checkAccountRate(eh)), 'should be locked after 5 failures');
  });

  it('reset clears the lockout', async () => {
    const eh = `eh-${Math.random()}`;
    for (let i = 0; i < 6; i++) await recordAccountFailure(eh);
    await resetAccountFailures(eh);
    assert.ok(await checkAccountRate(eh), 'should be allowed after reset');
  });
});

describe('rateLimiter — fingerprint lockout', () => {
  it('allows when no failures recorded', async () => {
    const id = `fp-${Math.random()}`;
    assert.ok(await checkFingerprintRate(id));
  });

  it('locks after 5 failures (schedule[5] = 30000ms)', async () => {
    const id = `fp-${Math.random()}`;
    for (let i = 0; i < 5; i++) await recordFingerprintFailure(id);
    assert.ok(!(await checkFingerprintRate(id)));
  });

  it('reset clears lockout', async () => {
    const id = `fp-${Math.random()}`;
    for (let i = 0; i < 6; i++) await recordFingerprintFailure(id);
    await resetFingerprintFailures(id);
    assert.ok(await checkFingerprintRate(id));
  });
});

describe('rateLimiter — register rate', () => {
  it(`allows first ${REGISTER_MAX_PER_WINDOW} registrations`, async () => {
    const ip = `reg-${Math.random()}`;
    for (let i = 0; i < REGISTER_MAX_PER_WINDOW; i++) assert.ok(await checkRegisterRate(ip));
    assert.ok(!(await checkRegisterRate(ip)));
  });
});

describe('rateLimiter — emergency rate', () => {
  it(`allows first ${EMERGENCY_MAX_PER_WINDOW} calls`, async () => {
    const ip = `emg-${Math.random()}`;
    for (let i = 0; i < EMERGENCY_MAX_PER_WINDOW; i++) assert.ok(await checkEmergencyRate(ip));
    assert.ok(!(await checkEmergencyRate(ip)));
  });
});

describe('rateLimiter — hints rate', () => {
  it(`allows first ${HINTS_MAX_PER_WINDOW} calls`, async () => {
    const ip = `hints-${Math.random()}`;
    for (let i = 0; i < HINTS_MAX_PER_WINDOW; i++) assert.ok(await checkHintsRate(ip));
    assert.ok(!(await checkHintsRate(ip)));
  });
});
