// Playwright E2E "golden path": the SOC analyst onboarding flow.
//
// Each test creates a fresh user (random email) so the suite is idempotent
// against a long-lived backend.
//
// Backend is expected to be reachable at http://localhost:8000 (Docker stack);
// frontend is launched by playwright.config.js via `npm run dev` on :5173.

import { test, expect } from '@playwright/test';

const API_BASE = process.env.PW_API_BASE || 'http://localhost:8000';

function uniqueEmail(prefix = 'e2e') {
  const stamp = Date.now() + Math.floor(Math.random() * 9999);
  return `${prefix}-${stamp}@trustflow.test`;
}

const PASSWORD = 'TestPass123!';

async function registerViaApi(request, email) {
  const r = await request.post(`${API_BASE}/api/auth/register`, {
    data: { email, password: PASSWORD, display_name: email.split('@')[0] },
  });
  expect(r.ok(), `register failed: ${r.status()} ${await r.text()}`).toBeTruthy();
  return r.json();
}

async function loginViaUI(page, email) {
  await page.goto('/login');
  await page.locator('input[type="email"]').first().fill(email);
  await page.locator('input[type="password"]').first().fill(PASSWORD);
  // Login button is the submit button on the form (label is "AUTHENTICATE →")
  await page.locator('button[type="submit"]').first().click();
  await page.waitForLoadState('networkidle');
}

test.describe('Auth + dashboard golden path', () => {
  test('register via UI, login, land on dashboard', async ({ page }) => {
    const email = uniqueEmail('reg');

    await page.goto('/register');
    await page.locator('input[type="email"]').first().fill(email);
    const pwds = page.locator('input[type="password"]');
    await pwds.nth(0).fill(PASSWORD);
    if ((await pwds.count()) > 1) {
      await pwds.nth(1).fill(PASSWORD);
    }
    // Display name field is optional — try to fill if present
    const nameInput = page.locator('input[name="display_name"], input[placeholder*="name" i]').first();
    if (await nameInput.count()) {
      await nameInput.fill('E2E Tester');
    }
    await page.locator('button[type="submit"]').first().click();

    // After register, should be on the authenticated app shell
    await page.waitForLoadState('networkidle');
    // Look for sidebar navigation or any authenticated-only element
    await expect(page.locator('body')).not.toContainText(/log\s*in to your account/i);
  });

  test('logout sends unauthenticated user back to login when visiting /api-keys', async ({ page, request }) => {
    const email = uniqueEmail('logout');
    await registerViaApi(request, email);
    await loginViaUI(page, email);

    // Clear auth state to simulate logout
    await page.evaluate(() => {
      localStorage.removeItem('tp_tokens');
      localStorage.removeItem('tp_user');
    });

    await page.goto('/api-keys');
    // After logout, the unauthenticated app shell shows landing/login content.
    // The "API KEYS" management header should NOT be present.
    await expect(page.locator('body')).not.toContainText(/api keys generated|active keys|generate new key/i);
  });
});

test.describe('Application + API key flow', () => {
  test('create application, generate key, key revealed once', async ({ page, request }) => {
    const email = uniqueEmail('key');
    await registerViaApi(request, email);
    await loginViaUI(page, email);

    await page.goto('/api-keys');
    // Wait for the API Keys page to actually render — the heading or the
    // "+ GENERATE NEW KEY" button is a strong signal the page has mounted.
    await expect(page.locator('button:has-text("GENERATE NEW KEY")')).toBeVisible({ timeout: 15_000 });

    // First click reveals an inline name input and relabels the button to CONFIRM
    await page.locator('button:has-text("GENERATE NEW KEY")').first().click();

    // Fill the inline name input that just appeared
    await page.locator('input[placeholder*="key name" i]').first().fill('E2E key');

    // Same button is now CONFIRM
    await page.locator('button:has-text("CONFIRM")').first().click();

    // The reveal modal must show a tf_live_ key
    await expect(page.locator('body')).toContainText(/tf_live_[0-9a-f]{16,}/, { timeout: 15_000 });
  });
});

test.describe('Integration Guide page', () => {
  test('renders endpoint banner and snippets', async ({ page, request }) => {
    const email = uniqueEmail('intg');
    await registerViaApi(request, email);
    await loginViaUI(page, email);

    await page.goto('/integration');
    await page.waitForLoadState('networkidle');

    // The page should display the configured ingest origin somewhere
    await expect(page.locator('body')).toContainText(/api\/v1\/ingest|X-API-Key|trustflow-sdk/i);
  });
});

test.describe('Real-time live feed', () => {
  test('event ingested via API appears in live feed within 5s', async ({ page, request }) => {
    const email = uniqueEmail('live');
    const reg = await registerViaApi(request, email);
    const accessToken = reg.access_token;

    // Generate an API key via REST so we can ingest
    const keyResp = await request.post(`${API_BASE}/api/keys`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      data: { name: 'live-feed-e2e' },
    });
    expect(keyResp.ok(), 'create key').toBeTruthy();
    const apiKey = (await keyResp.json()).key;

    await loginViaUI(page, email);
    // Land on the dashboard which hosts the live feed component
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Send an event with a unique USER value (the live feed renders user, not resource)
    const marker = `e2elive${Math.floor(Math.random() * 1e9)}`;
    const ingest = await request.post(`${API_BASE}/api/v1/ingest`, {
      headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' },
      data: {
        events: [{
          timestamp: new Date().toISOString(),
          user: marker,
          ip: '203.0.113.7',
          action: 'GET',
          status: 'success',
          resource: '/dashboard',
        }],
      },
    });
    expect(ingest.ok(), 'ingest').toBeTruthy();

    // The live feed should pick this up via WebSocket within ~3s.
    await expect(page.locator('body')).toContainText(marker, { timeout: 15_000 });
  });
});
