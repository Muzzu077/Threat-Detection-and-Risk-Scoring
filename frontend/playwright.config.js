import { defineConfig, devices } from '@playwright/test';

// Use the Vite dev server which proxies /api and /ws to the backend (port 8000).
// This avoids CORS configuration issues that come with hitting the production
// nginx build directly.
const PW_BASE_URL = process.env.PW_BASE_URL || 'http://localhost:5173';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 8_000 },
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: PW_BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    headless: true,
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: process.env.PW_NO_WEBSERVER ? undefined : {
    command: 'npm run dev',
    port: 5173,
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
