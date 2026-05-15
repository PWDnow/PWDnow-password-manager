/** @vitest-environment jsdom */
/**
 * Login KDF performance bench.
 *
 * Tracks the wall-clock cost of `deriveLocalKeys` so we can verify the
 * pure-JS-Argon2id → WASM-Argon2id-in-Worker migration actually moves the
 * needle. Numbers reported here go straight into LOGIN_PERFORMANCE_PLAN.md.
 *
 * Set PERF_BENCH=1 in the environment to run; skipped in normal CI to keep
 * `npm test` fast.
 */
import { describe, it } from 'vitest';
import { deriveLocalKeys } from '../crypto/keystore';

const SHOULD_RUN = process.env.PERF_BENCH === '1';

describe.skipIf(!SHOULD_RUN)('login KDF perf', () => {
  const password = 'CorrectHorseBatteryStaple!';
  const salt = '0123456789abcdef0123456789abcdef';
  const token = 'session-token-perf-bench';

  it('measures deriveLocalKeys (v1 + v2)', async () => {
    // Warm-up: pay the WASM-instantiation / module-init cost once so the
    // measured run reflects steady-state.
    await deriveLocalKeys(password, salt, token);

    const t0 = performance.now();
    const { v1, v2 } = await deriveLocalKeys(password, salt, token);
    const elapsed = performance.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[KDF perf] deriveLocalKeys total = ${elapsed.toFixed(0)} ms` +
                ` (v1=${!!v1} v2=${!!v2})`);
  }, 120_000);
});
