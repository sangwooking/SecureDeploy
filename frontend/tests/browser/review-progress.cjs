// Synthetic responses only; no backend, source upload, or paid provider calls.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fixture = require('../progress-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const errors = [], calls = [];
  let current = fixture(), fail = false;
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      const req = route.request(), parsed = new URL(req.url()), path = parsed.pathname;
      if (!path.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
      calls.push({ path, data: req.postData() });
      const json = data => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(data) });
      if (path === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
      if (path === '/api/auth/login') return json({ accessToken: 'fake-progress-test-only', tokenType: 'Bearer', user: { id: 1, email: 'test@example.invalid', name: 'Fixture' } });
      if (path === '/api/reviews') return json([{ ...current, riskSummary: current.comparison?.assessmentAfter, comparisonAvailable: !!current.comparison }]);
      if (path.endsWith('/vulnerabilities/status-summary')) return json({ projectId: 7, unchecked: 2, acknowledged: 0, inProgress: 0, resolved: 0, ignored: 0, resolutionRate: 0 });
      if (path === '/api/reviews/' + current.reviewId) return json(current);
      if (path === '/api/projects/7/reviews/upload' || path === '/api/projects/7/reviews/github') {
        if (fail) return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ message: '테스트용 재검사 실패' }) });
        current = { ...current, reviewId: current.reviewId + 1 };
        return json(current);
      }
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    });
    await page.goto(url);
    await page.getByLabel('이메일', { exact: true }).fill('test@example.invalid');
    await page.getByLabel('비밀번호', { exact: true }).fill('fake-password-for-browser-test');
    await page.locator('.auth-submit').click();
    await page.locator('.history-actions').getByRole('button', { name: '변화 보기', exact: true }).click();
    const nav = () => page.getByRole('navigation', { name: '분석 결과 메뉴' });
    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      await nav().getByRole('button', { name: '변화 보기', exact: true }).click();
      for (const label of ['해결된 문제', '아직 남아 있는 문제', '새로 발견된 문제', '상태가 달라진 문제', '비교 확인 불가']) {
        await page.getByRole('navigation', { name: '변화 분류' }).getByRole('button', { name: label + ' 1', exact: true }).click();
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${width} ${label}`);
        const card = page.locator('.security-progress > .vulnerability-list > article').first();
        await card.locator(':scope > .technical-details > summary').click();
        assert.ok((await card.innerText()).includes('synthetic-fingerprint'));
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await card.locator(':scope > .technical-details > summary').click();
      }
      await page.getByRole('navigation', { name: '변화 분류' }).getByRole('button', { name: '해결된 문제 1', exact: true }).click();
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: `/private/tmp/securedeploy-progress-${width}.png`, fullPage: true });
    }
    await page.getByRole('button', { name: '다시 검사', exact: true }).click();
    await page.locator('.rescan-form input[type=file]').setInputFiles({ name: 'renamed-fixed.zip', mimeType: 'application/zip', buffer: Buffer.from('synthetic never-uploaded-source') });
    await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
    await page.getByText('재검사가 완료되었습니다. 저장된 이전 분석과의 변화를 확인하세요.', { exact: true }).waitFor();
    assert.ok(calls.some(c => c.path === '/api/projects/7/reviews/upload' && c.data.includes('renamed-fixed.zip')));
    fail = true;
    await page.getByRole('button', { name: '다시 검사', exact: true }).click();
    await page.locator('.rescan-form input[type=file]').setInputFiles({ name: 'failed.zip', mimeType: 'application/zip', buffer: Buffer.from('synthetic') });
    await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: '테스트용 재검사 실패' }).waitFor();
    await page.locator('.security-progress').waitFor();
    fail = false;
    current.sourceType = 'GITHUB'; current.repositoryUrl = 'https://github.com/fixture/progress';
    await page.locator('.history-panel > summary').click();
    await page.locator('.history-item').click();
    await page.getByRole('button', { name: '다시 검사', exact: true }).click();
    assert.ok((await page.locator('.rescan-form').innerText()).includes(current.repositoryUrl));
    assert.equal(await page.locator('.rescan-form input[type=file]').count(), 0);
    await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
    await page.getByText('재검사가 완료되었습니다. 저장된 이전 분석과의 변화를 확인하세요.', { exact: true }).waitFor();
    assert.ok(calls.some(c => c.path.endsWith('/reviews/github') && JSON.parse(c.data).repositoryUrl === current.repositoryUrl));
    // Replay a real MockMvc upload->persistence->API response, if the backend tests have produced it.
    const recorded = '../build/progress-review-fixture.json';
    if (fs.existsSync(recorded)) {
      current = JSON.parse(fs.readFileSync(recorded, 'utf8'));
      if (!(await page.locator('.history-panel').evaluate(el => el.open))) await page.locator('.history-panel > summary').click();
      await page.getByRole('button', { name: '새로고침', exact: true }).click();
      await page.locator('.history-actions').getByRole('button', { name: '변화 보기', exact: true }).click();
      assert.ok((await page.locator('.security-progress').innerText()).includes('해결된 문제 1'));
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ result: 'passed', viewports: [1440, 390, 320], zipSameProject: true, githubSameProject: true,
      failurePreservesResult: true, backendFixtureReplay: fs.existsSync(recorded), realExternalCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
