// Page smoke spec: load every authenticated page and verify it renders
// something coherent (no React error boundary, no blank screen, no
// uncaught console errors that would break the page). Runs as one user
// for normal pages, then promotes them to admin and revisits the
// admin-only pages.

import { test, expect } from '@playwright/test';

const API_BASE = process.env.PW_API_BASE || 'http://localhost:8000';
const PASSWORD = 'TestPass123!';

function uniqueEmail(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 9999)}@trustflow.test`;
}

async function register(request, email) {
  const r = await request.post(`${API_BASE}/api/auth/register`, {
    data: { email, password: PASSWORD, display_name: email.split('@')[0] },
  });
  expect(r.ok()).toBeTruthy();
  return r.json();
}

async function loginViaUI(page, email) {
  await page.goto('/login');
  await page.locator('input[type="email"]').first().fill(email);
  await page.locator('input[type="password"]').first().fill(PASSWORD);
  await page.locator('button[type="submit"]').first().click();
  await page.waitForLoadState('networkidle');
}

async function pageLoadsClean(page, path, requiredFragment) {
  const consoleErrors = [];
  const onConsole = (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  };
  page.on('console', onConsole);

  await page.goto(path);
  await page.waitForLoadState('networkidle');

  // No React error overlay
  await expect(page.locator('body')).not.toContainText(/error boundary|render error|something went wrong/i);

  // Page-specific marker (page actually mounted)
  if (requiredFragment) {
    await expect(page.locator('body')).toContainText(requiredFragment, { timeout: 8_000 });
  }

  page.off('console', onConsole);

  // Fail loudly on truly fatal console errors. Filter known-noisy ones
  // (failed image fetches, recharts warnings, network errors that the UI
  // already handles).
  const fatal = consoleErrors.filter((e) =>
    !/Failed to load resource|recharts|favicon|net::ERR_|chunk load|404/i.test(e)
  );
  if (fatal.length) {
    throw new Error(`Console errors on ${path}:\n  ${fatal.join('\n  ')}`);
  }
}

// ───── Public / unauthenticated ──────────────────────────────────────────────

test.describe('Public pages', () => {
  test('LandingPage', async ({ page }) => {
    await pageLoadsClean(page, '/', /trustflow|login|register|sign in|cyber|security/i);
  });
  test('LoginPage', async ({ page }) => {
    await pageLoadsClean(page, '/login', /authenticate|access key|email/i);
  });
  test('RegisterPage', async ({ page }) => {
    await pageLoadsClean(page, '/register', /create|register|email|password/i);
  });
});

// ───── Authenticated user pages ──────────────────────────────────────────────

test.describe('Authenticated user pages', () => {
  let email;
  let userTokens;

  test.beforeAll(async ({ request }) => {
    email = uniqueEmail('user');
    userTokens = await register(request, email);
  });

  test.beforeEach(async ({ page }) => {
    await loginViaUI(page, email);
  });

  test('DashboardPage', async ({ page }) => {
    await pageLoadsClean(page, '/', /dashboard|telemetry|incidents|live|stats|risk/i);
  });
  test('ApplicationsPage', async ({ page }) => {
    await pageLoadsClean(page, '/applications', /application|create|register/i);
  });
  test('IncidentsPage', async ({ page }) => {
    await pageLoadsClean(page, '/incidents', /incident|status|risk|filter/i);
  });
  test('AttackGraphPage', async ({ page }) => {
    await pageLoadsClean(page, '/attack-graph', /graph|chain|attack/i);
  });
  test('ApiKeysPage', async ({ page }) => {
    await pageLoadsClean(page, '/api-keys', /api key|generate|prefix/i);
  });
  test('IntegrationGuidePage', async ({ page }) => {
    await pageLoadsClean(page, '/integration', /trustflow-sdk|x-api-key|ingest/i);
  });
  test('ThreatIntelPage', async ({ page }) => {
    await pageLoadsClean(page, '/threat-intel', /threat|intel|ip|reputation/i);
  });
  test('NotificationsPage', async ({ page }) => {
    await pageLoadsClean(page, '/notifications', /notification|telegram|email|slack|severity/i);
  });
  test('PlaybookBuilderPage', async ({ page }) => {
    await pageLoadsClean(page, '/playbook-builder', /playbook|trigger|step|builder/i);
  });
});

// ───── Admin route guard (non-admin) ────────────────────────────────────────

test.describe('Admin route guard for non-admin', () => {
  let email;

  test.beforeAll(async ({ request }) => {
    email = uniqueEmail('user');
    await register(request, email);
  });

  test.beforeEach(async ({ page }) => {
    await loginViaUI(page, email);
  });

  test('AdminUsers blocks non-admin', async ({ page }) => {
    await page.goto('/admin/users');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toContainText(/access denied|admin/i);
  });

  test('Compliance blocks non-admin', async ({ page }) => {
    await page.goto('/compliance');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toContainText(/access denied|admin/i);
  });

  test('Response blocks non-admin', async ({ page }) => {
    await page.goto('/response');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toContainText(/access denied|admin/i);
  });

  test('MLMetrics blocks non-admin', async ({ page }) => {
    await page.goto('/ml-metrics');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toContainText(/access denied|admin/i);
  });
});

// ───── Admin pages render for actual admins ────────────────────────────────
//
// To run as admin we register a fresh user, then invoke the in-container
// promotion script (docker exec). Skipped if the docker CLI isn't available.

import { execSync } from 'node:child_process';

function tryPromoteToAdmin(email) {
  try {
    execSync(
      `docker exec trustflow-api python /tmp/promote_admin.py ${email}`,
      { stdio: 'pipe' }
    );
    return true;
  } catch (e) {
    return false;
  }
}

test.describe('Admin pages render for admin', () => {
  let email;

  test.beforeAll(async ({ request }) => {
    email = uniqueEmail('admin');
    await register(request, email);
    const ok = tryPromoteToAdmin(email);
    test.skip(!ok, 'Admin promotion helper unavailable (docker exec failed)');
  });

  test.beforeEach(async ({ page }) => {
    await loginViaUI(page, email);
  });

  test('AdminUsersPage renders', async ({ page }) => {
    await pageLoadsClean(page, '/admin/users', /user|email|role|admin/i);
  });
  test('CompliancePage renders', async ({ page }) => {
    await pageLoadsClean(page, '/compliance', /soc|compliance|framework|report/i);
  });
  test('ResponsePage renders', async ({ page }) => {
    await pageLoadsClean(page, '/response', /response|blocked|disabled|action/i);
  });
  test('MLMetricsPage renders', async ({ page }) => {
    await pageLoadsClean(page, '/ml-metrics', /precision|recall|model|metric|f1|confusion/i);
  });
  test('MLLabPage renders', async ({ page }) => {
    await pageLoadsClean(page, '/ml-lab', /ensemble|train|zero[\s-]day|sequence|anomaly|model/i);
  });
  test('PlaybooksPage renders', async ({ page }) => {
    await pageLoadsClean(page, '/playbooks', /playbook|trigger|attack|step/i);
  });
});
