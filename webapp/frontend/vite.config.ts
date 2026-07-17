import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
