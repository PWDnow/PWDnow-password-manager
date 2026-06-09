import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act, cleanup } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';

// ── Mock the three React contexts Vault depends on ─────────────────────────────
const SC = 'text-green-600 bg-green-100 border-green-200 bg-green-500';
const credentials = [
  { id: 1, service: 'Discord', url: 'https://discord.com', username: 'gamer@x.com', password: 'p', status: 'Strong', statusColor: SC, folderId: null, tags: [] },
  { id: 2, service: 'GitHub',  url: 'https://github.com',  username: 'dev@x.com',   password: 'p', status: 'Strong', statusColor: SC, folderId: null, tags: [] },
  { id: 3, service: 'Gmail',   url: 'https://gmail.com',   username: 'me@gmail.com', password: 'p', status: 'Strong', statusColor: SC, folderId: null, tags: [] },
];

vi.mock('../context/VaultContext', () => ({
  useVault: () => ({
    folders: [],
    credentials,
    credentialsLoading: false,
    addCredential: vi.fn(),
    updateCredential: vi.fn(),
    deleteCredential: vi.fn(),
  }),
}));
vi.mock('../context/UserContext', () => ({ useUser: () => ({ profile: null }) }));
vi.mock('../context/NotificationContext', () => ({
  useNotification: () => ({ notifications: [], addNotification: vi.fn() }),
}));

// ── Stub heavy / irrelevant imports ────────────────────────────────────────────
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_k: string, fb?: string) => fb ?? _k, i18n: { language: 'en' } }),
  Trans: ({ children }: { children?: React.ReactNode }) => children ?? null,
}));
vi.mock('motion/react', () => {
  const passthrough = (tag: string) => (props: Record<string, unknown>) => {
    const { children, ...rest } = props as { children?: React.ReactNode };
    // Drop animation-only props that React would warn about.
    const clean: Record<string, unknown> = {};
    for (const k in rest) if (!['initial', 'animate', 'exit', 'transition', 'whileHover', 'whileTap', 'layout', 'variants'].includes(k)) clean[k] = (rest as Record<string, unknown>)[k];
    return require('react').createElement(tag, clean, children);
  };
  return {
    AnimatePresence: ({ children }: { children?: React.ReactNode }) => children ?? null,
    motion: new Proxy({}, { get: (_t, tag: string) => passthrough(tag) }),
  };
});
vi.mock('./AddCredential', () => ({ default: () => null }));
vi.mock('../components/ShareModal', () => ({ default: () => null }));
vi.mock('../components/SEO', () => ({ default: () => null }));
vi.mock('../utils/clipboardGuard', () => ({ secureClipboard: vi.fn() }));
vi.mock('../utils/logger', () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } }));
vi.mock('../utils/api', () => ({ apiFetch: vi.fn().mockResolvedValue(null) }));
vi.mock('../utils/localCrypto', () => ({ readDecryptedLocal: vi.fn().mockResolvedValue(null) }));
vi.mock('totp-generator', () => ({ TOTP: { generate: () => ({ otp: '000000', expires: Date.now() + 30000 }) } }));

import Vault from './Vault';

function renderAt(initialUrl: string) {
  const router = createMemoryRouter(
    [{ path: '/vault', element: <Vault /> }],
    { initialEntries: [initialUrl] },
  );
  render(<RouterProvider router={router} />);
  return router;
}

describe('Vault global search via ?q= URL param (bug #1)', () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => cleanup());

  it('filters to the matching credential when mounted at /vault?q=Discord', async () => {
    renderAt('/vault?q=Discord');
    await waitFor(() => expect(screen.getByText('Discord')).toBeTruthy());
    expect(screen.queryByText('GitHub')).toBeNull();
    expect(screen.queryByText('Gmail')).toBeNull();
  });

  it('re-syncs the filter when the ?q= param changes during SPA navigation', async () => {
    const router = renderAt('/vault?q=Discord');
    await waitFor(() => expect(screen.getByText('Discord')).toBeTruthy());
    expect(screen.queryByText('GitHub')).toBeNull();

    // Simulate the header global search navigating while Vault is already mounted.
    await act(async () => { await router.navigate('/vault?q=GitHub'); });

    await waitFor(() => expect(screen.getByText('GitHub')).toBeTruthy());
    expect(screen.queryByText('Discord')).toBeNull();
    expect(screen.queryByText('Gmail')).toBeNull();
  });

  it('shows all credentials when navigating to /vault with no query', async () => {
    const router = renderAt('/vault?q=Discord');
    await waitFor(() => expect(screen.getByText('Discord')).toBeTruthy());

    await act(async () => { await router.navigate('/vault'); });

    await waitFor(() => expect(screen.getByText('GitHub')).toBeTruthy());
    expect(screen.getByText('Discord')).toBeTruthy();
    expect(screen.getByText('Gmail')).toBeTruthy();
  });
});
