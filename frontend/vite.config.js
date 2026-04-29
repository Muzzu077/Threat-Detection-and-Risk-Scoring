import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Use regex so '/api/...' is proxied but SPA routes like '/api-keys'
      // (which is a React Router path) are NOT.
      '^/api/': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '^/ws/': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    }
  }
})
