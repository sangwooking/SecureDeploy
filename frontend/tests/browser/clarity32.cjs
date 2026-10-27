// Synthetic transport only. This checks React presentation, not live authentication or GitHub.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fixture = require('../result-fixture.cjs');
const scenarios = require('../summary-fixture.cjs');
const workspace = require('./workspace-fixture.cjs');
const origin = process.env.FRONTEND_URL || 'http://127.0.0.1:5482';
const output = process.env.UI32_OUTPUT || '/private/tmp/securedeploy-ui32';
const phase = process.env.CAPTURE_PHASE || 'after';
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
function clarityScenarios() {
  const cases = scenarios();
  const review = scenarios()[0].result;
  review.riskAssessment.prioritizedDeploymentAssessment = 'REVIEW_REQUIRED';
  review.resultSummary.policyAssessment = 'REVIEW_REQUIRED';
  cases.push({ id: 'review-required-perfect', result: review, view: 'SUMMARY', expected: ['REVIEW_REQUIRED', '100 / 100', 'PARTIAL'] });
  const development = fixture(), dep = development.sca.dependencyVulnerabilities[0];
  development.sca.components.push({ ecosystem: dep.ecosystem, packageName: dep.packageName, version: dep.installedVersion,
    scope: 'devDependencies', direct: false, sourceFile: 'package-lock.json', line: 12, versionResolution: 'EXACT',
    context: { environment: 'DEVELOPMENT', installedPath: 'node_modules/fixture-library', lockLine: 12,
      pathsComplete: false, limitations: ['통제 평가용 선언 경로'], paths: [] } });
  cases.push({ id: 'development-dependency', result: development, view: 'TECHNICAL',
    expected: ['개발·테스트 선언 경로', '간접 의존성', '고유 보안 공지 ID 수는 API에서 별도 집계하지 않으며'] });
  return cases;
}
(async () => {
  const browser = await chromium.launch({ headless: true });
  const checks = [];
  try {
    for (const width of [1440, 1280, 768, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const errors = [], external = [];
      let result = fixture(), denied = false;
      result.projectName = '보안 검증 웹 프로젝트 / 긴 이름과 경로 대조';
      page.on('pageerror', e => errors.push(e.message));
      await page.route('**/*', async route => {
        const request = route.request(), u = new URL(request.url());
        if (!u.pathname.startsWith('/api/')) {
          if (u.origin === origin) return route.continue();
          external.push(u.origin); return route.abort();
        }
        const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
        if (/\/api\/auth\/(login|signup)$/.test(u.pathname)) return json({ accessToken: 'synthetic-ui32', tokenType: 'Bearer', user: { id: 1, name: '검증 사용자', email: 'ui32@example.invalid' } });
        if (u.pathname === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
        if (u.pathname === '/api/github/connection') return json({ connected: false, repositories: [] });
        if (denied && u.pathname.startsWith('/api/projects/')) return json({ message: '접근 권한이 없습니다.' }, 403);
        const data = workspace(u.pathname, result);
        if (data) return json(data);
        if (u.pathname === `/api/reviews/${result.reviewId}`) return json(result);
        return json({ message: '합성 검증에 등록되지 않은 경로입니다.' }, 404);
      });
      const shot = async name => {
        await page.screenshot({ path: path.join(output, `${phase}-${name}-${width}.png`), fullPage: true });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${name} overflow ${width}`);
      };
      await page.goto(origin);
      await page.getByLabel('이메일', { exact: true }).waitFor();
      await shot('login');
      if (phase === 'after') {
        await page.getByRole('button', { name: '회원가입', exact: true }).click();
        await page.getByLabel('이름', { exact: true }).fill('검증 사용자');
      }
      await page.getByLabel('이메일', { exact: true }).fill('ui32@example.invalid');
      await page.getByLabel('비밀번호', { exact: true }).fill('Synthetic-UI32-only');
      await page.locator('.auth-submit').click();
      await page.locator('.workspace-project-row').first().waitFor();
      await shot('dashboard');
      if (phase === 'after') {
        const hash = await page.evaluate(() => location.hash);
        await page.locator('.skip-link').focus(); await page.keyboard.press('Enter');
        assert.equal(await page.evaluate(() => location.hash), hash);
        assert.ok(await page.locator('#workspace-main').evaluate(el => el === document.activeElement));
      }
      await page.locator('.workspace-project-row a').first().click();
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).waitFor();
      await shot('project');
      const nav = page.getByRole('navigation', { name: '프로젝트 메뉴' });
      await nav.getByRole('link', { name: '발견된 문제', exact: true }).click();
      await page.locator('.summary-facts').waitFor();
      await shot('result');
      await page.getByRole('button', { name: '반드시 처리할 문제 확인', exact: true }).click();
      await page.locator('.action-finding').first().waitFor();
      await shot('finding');
      await nav.getByRole('link', { name: '재검사', exact: true }).click();
      await page.locator('.rescan-form').waitFor();
      await shot('rescan');
      if (phase === 'after') {
        for (const scenario of clarityScenarios()) {
          result = scenario.result;
          await page.goto(`${origin}/#/projects/${result.projectId}/findings?view=${scenario.view}`);
          await page.reload();
          await page.locator('#result-content').waitFor();
          for (const expected of scenario.expected) assert.ok((await page.locator('#result-content').textContent()).includes(expected), `${scenario.id}: ${expected}`);
          if (scenario.view === 'SUMMARY') {
            const visible = await page.locator('.summary-facts').innerText();
            assert.ok(visible.includes(String(result.securityScore)));
            assert.ok(visible.includes(result.resultSummary?.coverageStatus ?? result.coverage.status));
          }
          assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${scenario.id} ${width}`);
          assert.equal(await page.locator('#result-content img').count(), 0);
        }
        result = fixture();
        await page.goto(`${origin}/#/projects/${result.projectId}/findings`); await page.reload();
        await page.locator('.summary-facts').waitFor();
        if (width === 1440) {
          await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
          await shot('zoom200');
          await page.evaluate(() => { document.documentElement.style.zoom = ''; });
        }
        await page.getByRole('link', { name: '대시보드', exact: true }).focus();
        assert.ok(await page.getByRole('link', { name: '대시보드', exact: true }).evaluate(el => getComputedStyle(el).outlineStyle !== 'none'));
        denied = true;
        await page.goto(`${origin}/#/projects/999/overview`);
        await page.getByRole('alert').filter({ hasText: '접근 권한' }).waitFor();
        assert.equal(await page.locator('.result-workspace').count(), 0);
        await page.getByRole('button', { name: '로그아웃', exact: true }).click();
        await page.getByRole('button', { name: '로그인', exact: true }).first().click();
        assert.equal(await page.evaluate(() => localStorage.getItem('securedeploy.accessToken')), null);
      }
      assert.deepEqual(errors, []); assert.deepEqual(external, []);
      checks.push({ width, phase, overflow: false, pageErrors: 0, externalCalls: 0 });
      await page.close();
    }
    console.log(JSON.stringify({ checks, transport: 'MOCK_ONLY', liveGitHub: false, liveBackend: false }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
