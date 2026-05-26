import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig(({mode}) => {
  // C-04 fix: API keys must never be baked into the browser bundle via Vite define.
  // Any AI/external API calls must go through a server-side proxy endpoint.
  return {
    plugins: [
      react(),
      tailwindcss(),
      VitePWA({
        injectRegister: false,
        registerType: 'autoUpdate',
        manifest: false, // use public/manifest.json directly
        workbox: {
          globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
          navigateFallback: '/index.html',
          // Never serve stale SPA shell for API calls, WS, or public share links
          navigateFallbackDenylist: [/^\/api\//, /^\/ws/, /^\/share\//],
          runtimeCaching: [
            {
              urlPattern: /^\/locales\//,
              handler: 'CacheFirst',
              options: {
                cacheName: 'locales-cache',
                expiration: { maxAgeSeconds: 86400, maxEntries: 50 },
              },
            },
          ],
          cleanupOutdatedCaches: true,
        },
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      // Never ship sourcemaps in production — they expose original source to anyone
      // who can reach the server.
      sourcemap: mode !== 'production',
      chunkSizeWarningLimit: 1500,
      rollupOptions: {
        // Suppress the expected kdbxweb/crypto externalization warning — kdbxweb is
        // designed for browsers and uses SubtleCrypto via its CryptoEngine internally.
        onwarn(warning, warn) {
          if (warning.message.includes('"crypto"') && warning.message.includes('kdbxweb')) return;
          warn(warning);
        },
        output: {
          // Function form: matches by module path, not by exact entry module ID.
          // Fixes the empty "vendor-react" chunk caused by React 19 using
          // `react-dom/client` (a different module ID from bare `react-dom`).
          manualChunks(id) {
            if (id.includes('/node_modules/react/') || id.includes('/node_modules/react-dom/') || id.includes('/node_modules/scheduler/')) {
              return 'vendor-react';
            }
            if (id.includes('/node_modules/react-router') || id.includes('/node_modules/@remix-run/')) {
              return 'vendor-router';
            }
            if (id.includes('/node_modules/i18next') || id.includes('/node_modules/react-i18next')) {
              return 'vendor-i18n';
            }
            if (id.includes('/node_modules/motion/') || id.includes('/node_modules/framer-motion/')) {
              return 'vendor-motion';
            }
            if (id.includes('/node_modules/lucide-react/')) {
              return 'vendor-icons';
            }
            if (id.includes('/node_modules/dompurify/')) {
              return 'vendor-dompurify';
            }
            if (id.includes('/node_modules/@msgpack/')) {
              return 'vendor-msgpack';
            }
            if (id.includes('/node_modules/@noble/')) {
              return 'vendor-noble';
            }
            if (id.includes('/node_modules/qrcode/')) {
              return 'vendor-qrcode';
            }
            if (id.includes('/node_modules/zxcvbn/')) {
              return 'vendor-zxcvbn';
            }
            if (id.includes('/node_modules/hash-wasm/')) {
              return 'vendor-hashwasm';
            }
            if (id.includes('/node_modules/@fingerprintjs/')) {
              return 'vendor-fingerprint';
            }
            if (id.includes('/node_modules/kdbxweb/') || id.includes('/node_modules/argon2-browser/')) {
              return 'vendor-crypto';
            }
          },
        },
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify — file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      proxy: {
        '/api': 'http://127.0.0.1:1234',
        '/ws': {
          target: 'ws://127.0.0.1:1234',
          ws: true
        }
      }
    },
    test: {
      environment: 'jsdom',
      // PWDNOW_ARGON2_FAST=1 switches Argon2id to reduced params (m=4 MiB, t=1)
      // so unit tests complete in milliseconds instead of minutes.
      env: { VITE_ARGON2_FAST: '1' },
    },
  };
});
