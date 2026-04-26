import { chromium } from 'playwright';

const BASE = 'http://localhost:8077';
const API = 'http://localhost:8000';

async function run() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const errors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') errors.push({ page: page.url(), text: msg.text() });
  });
  page.on('pageerror', err => {
    errors.push({ page: page.url(), text: err.message });
  });

  // 1. Register a fresh user
  console.log('\n=== REGISTER ===');
  const ts = Date.now();
  const regRes = await fetch(`${API}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: `test${ts}@example.com`,
      password: 'testpass123',
      full_name: 'Test User',
      org_name: `TestOrg ${ts}`
    })
  });
  const regData = await regRes.json();
  if (!regData.access_token) {
    console.log('Registration failed:', regData);
    await browser.close();
    process.exit(1);
  }
  const token = regData.access_token;
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  console.log('Registered OK, org_id:', payload.org_id);

  // Set auth in localStorage (Zustand persist)
  await page.goto(`${BASE}/login`);
  await page.evaluate((authData) => {
    localStorage.setItem('nis2-auth', JSON.stringify({
      state: {
        token: authData.token,
        user: { full_name: 'Test User', email: authData.email },
        orgId: authData.orgId
      },
      version: 0
    }));
  }, { token, email: `test${ts}@example.com`, orgId: payload.org_id });

  // 2. Check all pages
  const pages = [
    '/login',
    '/register',
    '/dashboard',
    '/dashboard/scans',
    '/dashboard/scans/new',
    '/dashboard/assets',
    '/dashboard/findings',
    '/dashboard/compliance',
    '/dashboard/settings',
    '/dashboard/settings/team',
    '/dashboard/settings/api-keys',
  ];

  const results = [];
  for (const path of pages) {
    errors.length = 0;
    console.log(`\n--- ${path} ---`);
    try {
      const resp = await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle', timeout: 15000 });
      await page.waitForTimeout(1000);
      const status = resp?.status() || 0;
      const pageErrors = [...errors];

      // Check for Next.js error overlay
      const hasErrorOverlay = await page.locator('[data-nextjs-dialog]').count() > 0 ||
                               await page.locator('#__next-build-error').count() > 0 ||
                               await page.locator('body').evaluate(el => el.innerText.includes('Unhandled Runtime Error')) ||
                               await page.locator('body').evaluate(el => el.innerText.includes('Server Error'));

      const screenshot = `/tmp/nis2-page-${path.replace(/\//g, '_')}.png`;
      await page.screenshot({ path: screenshot });

      const result = {
        path,
        status,
        hasErrorOverlay,
        consoleErrors: pageErrors.length,
        errors: pageErrors.map(e => e.text.substring(0, 200)),
        screenshot
      };
      results.push(result);

      if (hasErrorOverlay || pageErrors.length > 0) {
        console.log(`  STATUS: ${status} | ERRORS: ${pageErrors.length} | ERROR_OVERLAY: ${hasErrorOverlay}`);
        pageErrors.forEach(e => console.log(`  ERROR: ${e.text.substring(0, 150)}`));
      } else {
        console.log(`  OK (${status})`);
      }
    } catch (e) {
      console.log(`  TIMEOUT/CRASH: ${e.message.substring(0, 100)}`);
      results.push({ path, status: 0, hasErrorOverlay: true, consoleErrors: 1, errors: [e.message] });
    }
  }

  console.log('\n\n=== SUMMARY ===');
  const broken = results.filter(r => r.hasErrorOverlay || r.consoleErrors > 0 || r.status >= 500);
  const ok = results.filter(r => !r.hasErrorOverlay && r.consoleErrors === 0 && r.status < 500);
  console.log(`OK: ${ok.length} | BROKEN: ${broken.length}`);
  broken.forEach(r => {
    console.log(`  BROKEN: ${r.path} - ${r.errors[0]?.substring(0, 120) || 'error overlay'}`);
  });

  await browser.close();
}

run().catch(console.error);
