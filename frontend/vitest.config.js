import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.js'],
    // Don't try to run Playwright e2e specs through Vitest
    exclude: ['node_modules', 'dist', 'e2e/**', '**/*.e2e.*'],
  },
});
