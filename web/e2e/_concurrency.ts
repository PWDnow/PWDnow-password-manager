// Concurrency-test helpers. Used by every spec under e2e/race-*.spec.ts.
//
// The audit identified ~70% of server-side findings as instances of the same
// "load → await → save" pattern that leaks lost updates under parallel
// requests. The fix wraps every site in withUsersLock / withUserDirLock /
// withEmergencyRequestsLock. These helpers exist to make the race observable
// in a CI test: fire N requests in parallel, assert the final state would
// have been incorrect under the pre-patch code.
//
// Usage:
//   const results = await parallelFetch(11, (i) => ({
//     url: `${BASE}/api/auth/login`,
//     init: { method: 'POST', headers: { 'Content-Type': 'application/json' },
//             body: JSON.stringify({ email, password: 'wrong-' + i }) },
//   }));
//
// Each helper returns the full per-request result so the caller can assert
// on per-request and final-state invariants.

import { request, type APIRequestContext } from '@playwright/test';

export interface ParallelResult<T = unknown> {
  index: number;
  status: number;
  headers: Record<string, string>;
  body: T;
  /** Wall-clock ms from the first request fire to this response landing. */
  elapsedMs: number;
}

export async function parallelFetch<T = unknown>(
  n: number,
  builder: (i: number) => { url: string; init?: RequestInit },
  ctx?: APIRequestContext,
): Promise<Array<ParallelResult<T>>> {
  const apiContext = ctx ?? await request.newContext();
  const t0 = Date.now();
  const promises = Array.from({ length: n }, async (_, i) => {
    const { url, init } = builder(i);
    const method = (init?.method as 'GET' | 'POST' | 'PUT' | 'DELETE' | undefined) ?? 'GET';
    const headersInit = (init?.headers as Record<string, string> | undefined) ?? {};
    const reqOptions: Parameters<APIRequestContext['fetch']>[1] = {
      method,
      headers: headersInit,
      data: init?.body as string | undefined,
    };
    const res = await apiContext.fetch(url, reqOptions);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(res.headers())) headers[k.toLowerCase()] = v;
    let body: unknown = null;
    try { body = await res.json(); } catch { try { body = await res.text(); } catch {} }
    return {
      index: i,
      status: res.status(),
      headers,
      body: body as T,
      elapsedMs: Date.now() - t0,
    };
  });
  return Promise.all(promises);
}

/** Count results matching a predicate — handy for the duress-wipe spec. */
export function countWhere<T>(results: ParallelResult<T>[], pred: (r: ParallelResult<T>) => boolean): number {
  return results.filter(pred).length;
}

/** Assert that fewer than (or exactly) N results match the predicate. */
export function expectAtMost<T>(
  results: ParallelResult<T>[],
  n: number,
  pred: (r: ParallelResult<T>) => boolean,
  label = 'predicate',
): void {
  const c = countWhere(results, pred);
  if (c > n) {
    throw new Error(`expected at most ${n} ${label}, got ${c}`);
  }
}

/** Helper: build the body for a login attempt. */
export function loginBody(email: string, password: string, fingerprint?: object): string {
  return JSON.stringify({ email, password, browser: 'race-test', fingerprint });
}
