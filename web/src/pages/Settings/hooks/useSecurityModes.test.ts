import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

// ── Mocks ────────────────────────────────────────────────────────────────────
// readDecryptedLocal returns null → simulates a server-mode page reload where the
// in-memory local key is gone, so the only source of the SMTP config is the server.
const readDecryptedLocal = vi.fn().mockResolvedValue(null);
vi.mock('../../../utils/localCrypto', () => ({
  readDecryptedLocal: (...a: unknown[]) => readDecryptedLocal(...a),
  writeEncryptedLocal: vi.fn().mockResolvedValue(undefined),
}));

const apiFetch = vi.fn();
vi.mock('../../../utils/api', () => ({
  apiFetch: (...a: unknown[]) => apiFetch(...a),
}));

// securityModes internals are irrelevant to the SMTP bug — stub them out.
vi.mock('../../../utils/securityModes', () => ({
  getDuressModeConfig: () => ({ armed: false, maxAttempts: 5, attemptsRemaining: 5 }),
  getDuressModeConfigFull: vi.fn().mockResolvedValue({ armed: false, maxAttempts: 5, attemptsRemaining: 5 }),
  getTravelModeConfig: () => ({ enabled: false }),
  getTravelModeConfigAsync: vi.fn().mockResolvedValue({ enabled: false }),
  armDuressMode: vi.fn(),
  disarmDuressMode: vi.fn(),
  enableTravelMode: vi.fn(),
  disableTravelMode: vi.fn(),
}));

import { useSecurityModes } from './useSecurityModes';

describe('useSecurityModes — SMTP config load on mount (bug #2b)', () => {
  beforeEach(() => {
    apiFetch.mockReset();
    readDecryptedLocal.mockReset().mockResolvedValue(null);
    localStorage.clear();
  });

  it('loads the SMTP config from the server and maps it to EmailServerConfig', async () => {
    // Server GET /api/vault/smtp-config response shape (password stripped).
    apiFetch.mockResolvedValue({
      host: 'mail.binsearchlookup.com',
      port: 465,
      protocol: 'ssl_tls',
      username: 'no-reply@binsearchlookup.com',
      fromName: 'PWDnow',
      fromAddress: 'no-reply@binsearchlookup.com',
      mxVerified: true,
      passwordSet: true,
    });

    const { result } = renderHook(() => useSecurityModes());

    await waitFor(() => expect(result.current.emailServerConfig).not.toBeNull());

    expect(apiFetch).toHaveBeenCalledWith('/api/vault/smtp-config');
    const cfg = result.current.emailServerConfig!;
    expect(cfg.host).toBe('mail.binsearchlookup.com');
    expect(cfg.port).toBe(465);
    expect(cfg.user).toBe('no-reply@binsearchlookup.com'); // username → user
    expect(cfg.protocol).toBe('ssl_tls');
    expect(cfg.secure).toBe(true);                          // ssl_tls → secure
    expect(cfg.fromName).toBe('PWDnow');
  });

  it('stays null when the server has no SMTP config', async () => {
    apiFetch.mockResolvedValue(null);
    const { result } = renderHook(() => useSecurityModes());
    // Give the mount effect a tick to resolve.
    await waitFor(() => expect(apiFetch).toHaveBeenCalled());
    await Promise.resolve();
    expect(result.current.emailServerConfig).toBeNull();
  });

  it('does not throw when the server call fails (daemon/local-only mode)', async () => {
    apiFetch.mockRejectedValue(new Error('401 no session'));
    const { result } = renderHook(() => useSecurityModes());
    await waitFor(() => expect(apiFetch).toHaveBeenCalled());
    await Promise.resolve();
    expect(result.current.emailServerConfig).toBeNull();
  });

  it('prefers the local config (with password) but still reflects server when local is empty', async () => {
    // Local has a full config incl. password (daemon mode).
    readDecryptedLocal.mockResolvedValue(JSON.stringify({
      host: 'smtp.local', port: 587, user: 'me@local', pass: 'secret', protocol: 'starttls', secure: false,
    }));
    apiFetch.mockResolvedValue({
      host: 'smtp.local', port: 587, protocol: 'starttls', username: 'me@local', fromName: 'PWDnow', passwordSet: true,
    });

    const { result } = renderHook(() => useSecurityModes());
    await waitFor(() => expect(result.current.emailServerConfig).not.toBeNull());
    // Password from local copy must be preserved (server never returns it).
    expect(result.current.emailServerConfig!.pass).toBe('secret');
    expect(result.current.emailServerConfig!.host).toBe('smtp.local');
  });
});
