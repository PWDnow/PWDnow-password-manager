import { StrictMode, Suspense, lazy } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import DOMPurify from 'dompurify';
import { router } from './router';
import { VaultProvider } from './context/VaultContext';
import { NotificationProvider } from './context/NotificationContext';
import { ThemeProvider } from './context/ThemeContext';
import ErrorBoundary from './components/ErrorBoundary';
import './i18n';
import './index.css';

const NetworkStatus = lazy(() => import('./components/NetworkStatus'));

// Register a Trusted Types default policy backed by DOMPurify so that any
// innerHTML assignment passes through the sanitiser even when Trusted Types
// enforcement is enabled by CSP.  createScript/createScriptURL are blocked.
if (typeof window !== 'undefined' && window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy('default', {
    createHTML: (input: string) => DOMPurify.sanitize(input) as unknown as string,
    createScript: () => { throw new Error('Trusted Types: createScript blocked'); },
    // Allow service worker registration for /sw.js - all other script URLs remain blocked.
    createScriptURL: (url: string) => {
      try { if (new URL(url, location.href).pathname === '/sw.js') return url; } catch { /* ignore */ }
      throw new Error('Trusted Types: createScriptURL blocked');
    },
  });
}

// Manual service worker registration (deferred so it runs after Trusted Types setup)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
  });
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <HelmetProvider>
      <ErrorBoundary>
        <ThemeProvider>
          <NotificationProvider>
            <VaultProvider>
              <Suspense fallback={null}><NetworkStatus /></Suspense>
              <RouterProvider router={router} />
            </VaultProvider>
          </NotificationProvider>
        </ThemeProvider>
      </ErrorBoundary>
    </HelmetProvider>
  </StrictMode>,
);
