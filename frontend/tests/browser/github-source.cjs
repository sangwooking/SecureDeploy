// Entire browser scenario uses intercepted synthetic responses; no GitHub, accounts, or AI calls.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fixture = require('../progress-fixture.cjs');
const source = require('../github-source-fixture.cjs');
const workspace = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      let current = { ...fixture(), reviewId: 101, sourceType: 'GITHUB', repositoryUrl: 'https://github.com/fixture/monorepo', sourceMetadata: source() };
      current.comparison = null;
      const history = [structuredClone(current)], calls = [], errors = [];
      page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-github-source');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Source fixture', email: 'source@example.invalid' }));
      });
      await page.route('**/*', async route => {
        const req = route.request(), parsed = new URL(req.url()), path = parsed.pathname;
        if (!path.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
        const json = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
        if (path === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
        if (path.endsWith('/reviews/github')) {
          const data = req.postDataJSON(); calls.push({ path, data });
          assert.equal(data.scanMode, 'STANDARD');
          if (data.repositoryUrl.includes('private')) return json({ message: '저장소를 찾을 수 없거나 접근할 수 없습니다. 현재는 공개 GitHub 저장소만 지원합니다.' }, 400);
          if (path === '/api/projects/7/reviews/github') {
            assert.equal(data.repositoryUrl, current.repositoryUrl);
            const before = current;
            current = { ...structuredClone(current), reviewId: current.reviewId + 1,
              sourceMetadata: source(current.reviewId === 101 ? 'a'.repeat(40) : 'b'.repeat(40)) };
            current.comparison = { ...fixture().comparison, baselineReviewId: before.reviewId, currentReviewId: current.reviewId,
              sourceBefore: before.sourceMetadata, sourceAfter: current.sourceMetadata };
            history.unshift(structuredClone(current));
          }
          return json(current);
        }
        const data = workspace(path, current, history);
        if (data) return json(data);
        const saved = history.find(r => path === `/api/reviews/${r.reviewId}`);
        if (saved) return json(saved);
        return json({ message: '찾을 수 없습니다.' }, 404);
      });
      const fits = async () => assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow at ${width}`);
      await page.goto(`${url}/#/new`);
      await page.getByRole('button', { name: 'GitHub URL 입력', exact: true }).click();
      await page.getByLabel('Repository URL', { exact: true }).fill('https://github.com/fixture/private');
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      await page.getByRole('alert').filter({ hasText: '공개 GitHub 저장소만 지원' }).waitFor();
      await fits();
      await page.getByLabel('Repository URL', { exact: true }).fill(current.repositoryUrl);
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      await page.getByRole('heading', { name: '분석한 GitHub 버전', exact: true }).waitFor();
      await page.getByText('develop', { exact: true }).waitFor();
      await page.getByText('aaaaaaa', { exact: true }).waitFor();
      await page.getByText('소스 기술 정보 보기', { exact: true }).click();
      await page.getByText('a'.repeat(40), { exact: true }).waitFor();
      await fits();
      await page.screenshot({ path: `/private/tmp/securedeploy-github-overview-${width}.png`, fullPage: true });
      const projectNav = page.getByRole('navigation', { name: '프로젝트 메뉴' });
      for (const expected of ['이전 검사와 동일한 commit입니다.', '서로 다른 commit을 분석했습니다.']) {
        await projectNav.getByRole('link', { name: '재검사', exact: true }).click();
        assert.equal(await page.locator('.rescan-form input[type=file]').count(), 0);
        await page.getByRole('button', { name: '대상 확인 후 다시 검사', exact: true }).click();
        await page.getByText(expected, { exact: true }).waitFor();
        await fits();
      }
      await page.screenshot({ path: `/private/tmp/securedeploy-github-comparison-${width}.png`, fullPage: true });
      await projectNav.getByRole('link', { name: '분석 이력', exact: true }).click();
      const rows = page.locator('.workspace-history-row');
      await rows.first().waitFor();
      assert.equal(await rows.count(), 3);
      assert.ok((await rows.first().innerText()).includes('bbbbbbb'));
      assert.ok((await rows.last().innerText()).includes('aaaaaaa'));
      await rows.last().getByRole('link', { name: '결과 보기', exact: true }).click();
      await page.getByText(/과거 분석 #101/).waitFor();
      assert.ok((await page.locator('.result-workspace > .github-source').innerText()).includes('aaaaaaa'));
      assert.ok(!(await page.locator('.result-workspace > .github-source').innerText()).includes('bbbbbbb'));
      await fits();
      assert.equal(calls.length, 4);
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log(JSON.stringify({ result: 'passed', widths: [1440, 390, 320], newGithub: true, privateError: true,
      metadata: true, sameCommit: true, changedCommit: true, historicalCommit: true, externalCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
