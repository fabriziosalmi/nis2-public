import { chromium } from 'playwright';

const BASE = 'http://localhost:8077';
const API = 'http://localhost:8000';

async function run() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const pageErrors = [];
  page.on('pageerror', err => pageErrors.push(err.message));

  // Register via API
  const ts = Date.now();
  const email = `e2e${ts}@testdomain.com`;
  const password = 'testpass123';
  const regRes = await fetch(`${API}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, full_name: 'E2E Tester', org_name: `E2E Org ${ts}` })
  });
  const regData = await regRes.json();
  const token = regData.access_token;
  const jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  console.log(`Registered: ${email}, org: ${jwtPayload.org_id}\n`);

  // Inject auth into localStorage
  await page.goto(`${BASE}/login`);
  await page.evaluate(({ token, email, orgId }) => {
    localStorage.setItem('nis2-auth', JSON.stringify({
      state: { token, user: { full_name: 'E2E Tester', email }, orgId },
      version: 0
    }));
  }, { token, email, orgId: jwtPayload.org_id });
  // Reload so Zustand picks up localStorage
  await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle', timeout: 10000 });
  await page.waitForTimeout(2000);

  // Now check all dashboard pages
  const routes = [
    { path: '/dashboard', name: 'Dashboard' },
    { path: '/dashboard/scans', name: 'Scans List' },
    { path: '/dashboard/scans/new', name: 'New Scan' },
    { path: '/dashboard/assets', name: 'Assets' },
    { path: '/dashboard/findings', name: 'Findings' },
    { path: '/dashboard/compliance', name: 'Compliance' },
    { path: '/dashboard/settings', name: 'Settings' },
    { path: '/dashboard/settings/team', name: 'Team' },
    { path: '/dashboard/settings/api-keys', name: 'API Keys' },
  ];

  const broken = [];
  for (const route of routes) {
    pageErrors.length = 0;
    try {
      await page.goto(`${BASE}${route.path}`, { waitUntil: 'networkidle', timeout: 15000 });
      await page.waitForTimeout(500);

      // Check for error overlay text
      const bodyText = await page.locator('body').innerText();
      const hasError = bodyText.includes('Unhandled Runtime Error') ||
                       bodyText.includes('Server Error') ||
                       bodyText.includes('Application error') ||
                       bodyText.includes('Internal Server Error');

      // Check for sidebar (proves dashboard layout rendered)
      const hasSidebar = await page.locator('text=Dashboard').first().isVisible().catch(() => false);

      const ssPath = `/tmp/nis2-${route.path.replace(/\//g, '_')}.png`;
      await page.screenshot({ path: ssPath });

      const status = hasError ? 'ERROR' : !hasSidebar ? 'NO_LAYOUT' : 'OK';
      const icon = status === 'OK' ? '✓' : '✗';
      const errs = pageErrors.length > 0 ? ` (${pageErrors.length} console errors)` : '';

      console.log(`${icon} ${route.name.padEnd(15)} ${route.path.padEnd(35)} ${status}${errs}`);

      if (status !== 'OK' || pageErrors.length > 0) {
        broken.push({
          ...route,
          status,
          errors: [...pageErrors],
          bodySnippet: hasError ? bodyText.substring(0, 300) : null,
          screenshot: ssPath,
        });
      }
    } catch (e) {
      console.log(`✗ ${route.name.padEnd(15)} ${route.path.padEnd(35)} TIMEOUT: ${e.message.substring(0, 80)}`);
      broken.push({ ...route, status: 'TIMEOUT', errors: [e.message] });
    }
  }

  // Also test login flow through the UI
  console.log('\n--- Login Flow Test ---');
  await page.evaluate(() => localStorage.clear());
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForTimeout(3000);
  const finalUrl = page.url();
  const loginOk = finalUrl.includes('/dashboard');
  console.log(`${loginOk ? '✓' : '✗'} Login flow -> ${finalUrl}`);
  if (!loginOk) {
    const ss = `/tmp/nis2-login-flow-result.png`;
    await page.screenshot({ path: ss });
    broken.push({ path: '/login-flow', name: 'Login Flow', status: 'FAILED', screenshot: ss });
  }

  console.log(`\n=== RESULT: ${broken.length === 0 ? 'ALL OK' : `${broken.length} ISSUES`} ===`);
  for (const b of broken) {
    console.log(`\n  ISSUE: ${b.name} (${b.path})`);
    console.log(`  Status: ${b.status}`);
    if (b.errors?.length) console.log(`  Errors: ${b.errors.map(e => e.substring(0, 150)).join('\n          ')}`);
    if (b.bodySnippet) console.log(`  Body: ${b.bodySnippet.substring(0, 200)}`);
    if (b.screenshot) console.log(`  Screenshot: ${b.screenshot}`);
  }

  await browser.close();
  process.exit(broken.length > 0 ? 1 : 0);
}

run().catch(e => { console.error(e); process.exit(1); });
