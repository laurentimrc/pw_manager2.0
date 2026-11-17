import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { registerSW } from 'virtual:pwa-register'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

// PWA service worker registration. We use the "prompt" update strategy
// (matching `registerType: 'prompt'` in vite.config.ts) rather than
// silent auto-update: this is a password manager, and a user may have a
// decrypted secret on screen or be mid-way through a form when a new
// version is deployed. A silent background reload could discard unsaved
// input or yank a revealed secret off-screen without warning. Instead we
// only reload when the user explicitly confirms. This never affects
// `/api/*` calls either way - see the workbox `runtimeCaching` NetworkOnly
// rule in vite.config.ts.
const updateSW = registerSW({
  onNeedRefresh() {
    const shouldReload = window.confirm(
      'È disponibile una nuova versione di Password Manager Pro. Ricaricare ora?',
    )
    if (shouldReload) {
      void updateSW()
    }
  },
  onOfflineReady() {
    // No UI needed: this only means the static app shell is cached, not
    // that the app is usable offline in any meaningful sense (every real
    // action still requires the backend over the network).
  },
})
