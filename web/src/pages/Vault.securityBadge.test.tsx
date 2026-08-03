import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router';

// A passkey credential is the shape most likely to be missing `statusColor`
// in real, older vault data: non-'login' credentialTypes have never had a
// meaningful password-strength value, and the type declares `statusColor` as
// a required string even though real (especially historical) vault data
// doesn't actually guarantee it's present.
const passkeyCredential = {
  id: 1,
  service: 'GitHub',
  url: '',
  username: '',
  password: '',
  status: 'good',
  statusColor: undefined as unknown as string,
  folderId: null,
  tags: [],
  credentialType: 'passkey' as const,
  rpId: 'github.com',
  rpName: 'GitHub',
};

vi.mock('../context/VaultContext', () => ({
  useVault: () => ({
    folders: [],
    credentials: [passkeyCredential],
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

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_k: string, fb?: string) => fb ?? _k, i18n: { language: 'en' } }),
  Trans: ({ children }: { children?: React.ReactNode }) => children ?? null,
}));
vi.mock('motion/react', () => {
  const passthrough = (tag: string) => (props: Record<string, unknown>) => {
    const { children, ...rest } = props as { children?: React.ReactNode };
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

describe('Vault does not crash on a non-login credential with a missing statusColor', () => {
  afterEach(() => cleanup());

  it('renders the passkey credential without throwing "Cannot read properties of undefined (reading \'split\')"', async () => {
    expect(() => renderAt('/vault')).not.toThrow();
    await waitFor(() => expect(screen.getAllByText('GitHub').length).toBeGreaterThan(0));
  });
});
