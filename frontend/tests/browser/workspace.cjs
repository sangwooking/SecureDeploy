// Mock transport only; no real accounts, backend, or external AI calls.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fixture = require('../result-fixture.cjs');
const workspaceFixture = require('./workspace-fixture.cjs');
const policy = require('../upload-policy-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';
const empty = { projectCount: 0, analyzedProjectCount: 0, blockedProjectCount: 0,
  reviewRequiredProjectCount: 0, unassessedProjectCount: 0, projects: [] };

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const result = fixture(); result.projectName = 'Private fixture A';
      let unavailable = true, noReviews = false, deleted = false, hold = false, release;
      let deletes = 0;
      const errors = []; page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-workspace-A');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Fixture A', email: 'a@workspace.test.invalid' }));
      });
      await page.route('**/*', async route => {
        const request = route.request(), parsed = new URL(request.url()), path = parsed.pathname;
        if (!path.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
        const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
        if (path === '/api/auth/login') return json({ accessToken: 'synthetic-workspace-B', tokenType: 'Bearer', user: { id: 2, name: 'Fixture B', email: 'b@workspace.test.invalid' } });
        if (path === '/api/reviews/upload-policy') return json(policy);
        const userB = request.headers().authorization === 'Bearer synthetic-workspace-B';
        if (path === '/api/workspace') {
          if (userB || deleted) return json(empty);
          if (unavailable) return json({ message: '테스트용 조회 실패' }, 503);
          if (hold) { await new Promise(resolve => { release = resolve; }); }
          return json(workspaceFixture(path, result));
        }
        if (userB) return json({ message: '본인 소유 프로젝트에만 접근할 수 있습니다.' }, 403);
        if (path === '/api/projects/7' && request.method() === 'DELETE') { deletes++; deleted = true; return json({ message: '삭제되었습니다.' }); }
        if (path === '/api/projects/7' && noReviews) return json({ ...workspaceFixture(path, result), latestReview: null, reviewCount: 0 });
        if (path === '/api/projects/7/reviews' && noReviews) return json([]);
        const data = workspaceFixture(path, result);
        if (data) return json(data);
        if (path === `/api/reviews/${result.reviewId}`) return json(result);
        return json({ message: '찾을 수 없습니다.' }, 404);
      });
      await page.goto(url);
      await page.getByRole('alert').filter({ hasText: '조회 실패' }).waitFor();
      assert.equal(await page.getByText('Private fixture A', { exact: true }).count(), 0);
      unavailable = false;
      await page.getByRole('button', { name: '다시 불러오기', exact: true }).click();
      await page.getByRole('link', { name: '프로젝트 열기', exact: true }).waitFor();
      const nav = page.getByRole('navigation', { name: '앱 메뉴' });
      await nav.getByRole('link', { name: '내 프로젝트', exact: true }).click();
      await page.getByRole('heading', { name: '내 프로젝트 (1)', exact: true }).waitFor();
      noReviews = true;
      await page.getByRole('link', { name: '프로젝트 열기', exact: true }).click();
      await page.getByText('아직 분석 결과가 없습니다.', { exact: true }).waitFor();
      const projectNav = page.getByRole('navigation', { name: '프로젝트 메뉴' });
      await projectNav.getByRole('link', { name: '분석 이력', exact: true }).click();
      await page.getByText('저장된 분석 결과가 없습니다.', { exact: true }).waitFor();
      await projectNav.getByRole('link', { name: '재검사', exact: true }).click();
      await page.locator('.rescan-form input[type=file]').waitFor();
      await projectNav.getByRole('link', { name: '프로젝트 설정', exact: true }).click();
      page.once('dialog', dialog => dialog.dismiss());
      await page.getByRole('button', { name: '프로젝트 삭제', exact: true }).click();
      assert.equal(deletes, 0);
      page.once('dialog', dialog => dialog.accept());
      await page.getByRole('button', { name: '프로젝트 삭제', exact: true }).click();
      await page.getByRole('heading', { name: '내 프로젝트 (0)', exact: true }).waitFor();
      assert.equal(deletes, 1);

      // Complete an old user's request only after the new user's workspace is visible.
      deleted = false; noReviews = false; hold = true;
      await nav.getByRole('link', { name: '대시보드', exact: true }).click();
      while (!release) await page.waitForTimeout(20);
      await page.getByRole('button', { name: '로그아웃', exact: true }).click();
      await page.getByLabel('이메일', { exact: true }).fill('b@workspace.test.invalid');
      await page.getByLabel('비밀번호', { exact: true }).fill('Synthetic-workspace-fixture');
      await page.locator('.auth-submit').click();
      await page.getByRole('heading', { name: 'Fixture B님의 SecureDeploy', exact: true }).waitFor();
      release(); await page.waitForTimeout(100);
      assert.equal(await page.getByText('Private fixture A', { exact: true }).count(), 0);
      await page.evaluate(() => { location.hash = '#/projects/7/findings'; });
      await page.getByRole('alert').filter({ hasText: '본인 소유' }).waitFor();
      assert.equal(await page.locator('.result-workspace').count(), 0);
      await nav.getByRole('link', { name: '계정', exact: true }).click();
      await page.getByText('b@workspace.test.invalid', { exact: true }).waitFor();
      assert.ok(!(await page.locator('body').innerText()).includes('a@workspace.test.invalid'));
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log(JSON.stringify({ result: 'passed', widths: [1440, 390, 320], errorRetry: true, emptyProject: true,
      confirmedDeletion: true, logoutLogin: true, staleUserResponseDiscarded: true, foreignProjectHidden: true, externalCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
