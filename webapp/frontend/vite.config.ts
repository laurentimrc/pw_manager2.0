import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'
import path from 'node:path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      // "generateSW": lets workbox build the service worker from this
      // config instead of us hand-writing one - the standard, low-maintenance
      // path for a precache-the-app-shell PWA like this one.
      strategies: 'generateSW',
      registerType: 'prompt',
      injectRegister: false, // we register manually in main.tsx via virtual:pwa-register
      includeAssets: ['favicon.svg', 'apple-touch-icon.png'],
      manifest: {
        name: 'Password Manager Pro',
        short_name: 'PW Manager',
        description: 'Password manager locale e cifrato, con note sicure, carte di pagamento e TOTP.',
        start_url: '/',
        display: 'standalone',
        background_color: '#f9fafc',
        theme_color: '#186de7',
        icons: [
          { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
          { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
          { src: '/icons/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: {
        // Never let the generated SW serve a cached HTML shell for API
        // routes (navigateFallback only applies to navigation requests,
        // but this keeps it explicit and future-proof).
        navigateFallbackDenylist: [/^\/api\//],
        // SECURITY: this is a password manager - API responses carry
        // session-gated decrypted secrets (passwords, TOTP secrets, card
        // numbers, note contents) and must NEVER be written to the Cache
        // Storage API or served stale/offline. `url.pathname` is checked
        // (not a same-origin RegExp route) so this also covers the dev
        // setup where the API lives on a different origin/port than the
        // frontend. NetworkOnly = always hit the real network, every time,
        // so the existing credentials:'include' session-cookie flow and
        // the 15-minute server-side session timeout keep working exactly
        // as before the service worker existed.
        runtimeCaching: [
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/'),
            handler: 'NetworkOnly',
          },
        ],
      },
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    // Il backend FastAPI gira solo su 127.0.0.1: usiamo lo stesso host (non
    // "localhost") anche per il dev server, così i cookie di sessione
    // httpOnly/SameSite=Strict vengono considerati same-site tra le due porte.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
})
