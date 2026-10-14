// Browser-only fixtures: no real credentials, backend calls, or AI requests.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const resultFixture = require('../progress-fixture.cjs');
const workspaceFixture = require('./workspace-fixture.cjs');
const policy = require('../upload-policy-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securedeploy-upload-ui-'));
  const oversized = path.join(dir, 'oversized.zip');
  const fd = fs.openSync(oversized, 'w');
  fs.ftruncateSync(fd, policy.maxZipBytes + 1); fs.closeSync(fd);
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: width === 1440 ? 1000 : 844 } });
      let uploads = 0, rescans = 0, policyUnavailable = true;
      const errors = [];
      let result = resultFixture();
      page.on('pageerror', err => errors.push(err.message));
      await page.route('**/*', async route => {
        const req = route.request(), parsed = new URL(req.url()), endpoint = parsed.pathname;
        if (!endpoint.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
        const json = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
        const workspace = workspaceFixture(endpoint, result);
        if (workspace) return json(workspace);
        if (endpoint === `/api/reviews/${result.reviewId}`) return json(result);
        if (endpoint === '/api/auth/login') return json({ accessToken: 'synthetic-upload-test', tokenType: 'Bearer', user: { id: 1, email: 'fixture@test.invalid', name: 'Fixture' } });
        if (endpoint === '/api/reviews/upload-policy') return policyUnavailable ? json({ message: '테스트용 제한 조회 실패' }, 503) : json(policy);
        if (endpoint === '/api/reviews') return json([]);
        if (endpoint === '/api/reviews/upload') { uploads++; return json(result); }
        if (endpoint === '/api/projects/7/reviews/upload') { rescans++; result = { ...result, reviewId: result.reviewId + 1 }; return json(result); }
        if (endpoint.endsWith('/vulnerabilities/status-summary')) return json({ projectId: 7, unchecked: 2, acknowledged: 0, inProgress: 0, resolved: 0, ignored: 0, resolutionRate: 0 });
        return json({}, 404);
      });
      await page.goto(url);
      await page.getByLabel('이메일', { exact: true }).fill('fixture@test.invalid');
      await page.getByLabel('비밀번호', { exact: true }).fill('Synthetic-test-password');
      await page.locator('.auth-submit').click();
      await page.getByRole('navigation', { name: '앱 메뉴' }).getByRole('link', { name: '새 프로젝트', exact: true }).click();
      await page.getByRole('alert').filter({ hasText: '제한 조회 실패' }).waitFor();
      assert.equal(await page.getByRole('button', { name: '분석 시작', exact: true }).isDisabled(), true);
      policyUnavailable = false;
      await page.getByRole('button', { name: '제한 정보 다시 확인', exact: true }).click();
      await page.getByText('ZIP 파일 최대 200MB', { exact: true }).waitFor();
      assert.ok((await page.locator('.zip-upload-guidance').innerText()).includes('node_modules, .git, build, dist, target'));
      await page.locator('.analysis-entry input[type=file]').setInputFiles(oversized);
      await page.getByRole('alert').filter({ hasText: '프로젝트 파일은 최대 200MB' }).waitFor();
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      assert.equal(uploads, 0);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({ path: `/private/tmp/securedeploy-upload-limit-${width}.png`, fullPage: true });
      await page.locator('.analysis-entry input[type=file]').setInputFiles({ name: 'normal.zip', mimeType: 'application/zip', buffer: Buffer.from('synthetic-mocked-zip') });
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).waitFor();
      assert.equal(uploads, 1);
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).getByRole('link', { name: '재검사', exact: true }).click();
      await page.locator('.rescan-form').getByText('ZIP 파일 최대 200MB', { exact: true }).waitFor();
      await page.locator('.rescan-form input[type=file]').setInputFiles(oversized);
      await page.locator('.rescan-form').getByRole('alert').filter({ hasText: '프로젝트 파일은 최대 200MB' }).waitFor();
      await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
      assert.equal(rescans, 0);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({ path: `/private/tmp/securedeploy-rescan-limit-${width}.png`, fullPage: true });
      await page.locator('.rescan-form input[type=file]').setInputFiles({ name: 'fixed.zip', mimeType: 'application/zip', buffer: Buffer.from('synthetic-mocked-zip') });
      await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
      await page.getByText('재검사를 완료했습니다. 이전 분석과 현재 분석의 변화를 확인하세요.', { exact: true }).waitFor();
      assert.equal(rescans, 1);
      await page.locator('.security-progress').waitFor();
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log(JSON.stringify({ result: 'passed', widths: [1440, 390, 320], mainAndRescanLimits: true,
      rejectedBeforeRequest: true, policyFailureAndRetry: true, normalUploadAndRescan: true, realExternalCalls: 0 }));
  } finally { await browser.close(); fs.rmSync(dir, { recursive: true, force: true }); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
