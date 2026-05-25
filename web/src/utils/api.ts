// Canonical CSRF / fetch utilities.
// Single source of truth — import from here; do not redefine locally.

export class ApiError extends Error {
  public data: any;
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    try {
      this.data = JSON.parse(message);
    } catch {
      this.data = {};
    }
  }
}

/** Read the _pwd_csrf cookie value ('' when absent or SSR). */
export function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const m = document.cookie.match(/(?:^|;\s*)_pwd_csrf=([^;]*)/);
  return m ? m[1] : '';
}

/** True when a server session (_pwd_csrf cookie) is present. */
export function hasServerSession(): boolean {
  if (typeof document === 'undefined') return false;
  return /(?:^|;\s*)_pwd_csrf=/.test(document.cookie);
}

/**
 * Typed fetch wrapper.
 * - Attaches `credentials: 'same-origin'` and `Content-Type: application/json` automatically.
 * - Injects `X-CSRF-Token` header on every mutating request (non-GET/HEAD).
 * - Throws `ApiError` on non-2xx responses.
 * - Returns `undefined as T` for 204 No Content.
 */
export async function apiFetch<T = unknown>(url: string, opts: RequestInit = {}): Promise<T> {
  const method = (opts.method ?? 'GET').toUpperCase();
  const mutating = method !== 'GET' && method !== 'HEAD';
  const headers = new Headers(opts.headers as HeadersInit | undefined);
  if (opts.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (mutating) {
    const token = getCsrfToken();
    if (token) headers.set('X-CSRF-Token', token);
  }
  const res = await fetch(url, { credentials: 'same-origin', ...opts, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new ApiError(res.status, body);
  }
  return res.status === 204 ? (undefined as T) : (res.json() as Promise<T>);
}
