// Synthetic API transport only; no real user project is ever deleted.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fixture = require('../result-fixture.cjs');
const workspace = require('./workspace-fixture.cjs');
const origin = process.env.FRONTEND_URL || 'http://127.0.0.1:5486';
const output = process.env.UI336_OUTPUT || '/private/tmp/securedeploy-ui336';
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
(async () => {
  const browser = await chromium.launch();
  const checks = [];
  try {
    for (const width of [1440, 1280, 768, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const result = fixture(), data = workspace('/api/workspace', result);
      const first = data.projects[0], name = first.name;
      data.projects = [first, { ...first, projectId: 8, name: '아주긴프로젝트이름으로도메뉴와상태및건수가서로겹치지않아야하는서비스', latestReview: null }];
      data.projectCount = 2;
      let status = 409, requests = [], pending;
      const errors = [], external = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-management-only');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Fixture', email: 'fixture@example.invalid' }));
      });
      await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        if (!url.pathname.startsWith('/api/')) {
          if (url.origin === origin) return route.continue();
          external.push(url.origin); return route.abort();
        }
        const json = (body, code = 200) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(body) });
        if (request.method() === 'DELETE') {
          requests.push(url.pathname);
          if (status === 200) {
            await new Promise(resolve => { pending = resolve; });
            data.projects = data.projects.filter(project => project.projectId !== first.projectId);
            data.projectCount = data.projects.length;
            return json({ message: '삭제했습니다.' });
          }
          return json({ message: status === 409 ? '수정 작업 공간을 먼저 닫아 주세요.' : status === 403 ? '삭제 권한이 없습니다.' : '삭제 처리 중 오류가 발생했습니다.' }, status);
        }
        if (url.pathname === '/api/workspace') return json(data);
        if (url.pathname === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
        const body = workspace(url.pathname, result);
        return json(body || {}, body ? 200 : 404);
      });
      const overflow = async () => assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow ${width}`);
      const shot = async label => { await overflow(); await page.screenshot({ path: `${output}/after-${label}-${width}.png`, fullPage: true }); };
      await page.goto(origin + '/#/projects');
      const rows = page.locator('.workspace-project-list .workspace-project-row');
      await rows.first().waitFor();
      assert.equal(await rows.count(), 2);
      assert.equal(await page.getByRole('link', { name: '프로젝트 열기', exact: true }).count(), 0);
      await shot('projects');
      const manage = page.getByLabel(`${name} 관리`, { exact: true });
      await manage.focus(); await page.keyboard.press('Enter');
      await page.getByRole('link', { name: '프로젝트 열기', exact: true }).waitFor();
      await shot('project-menu');
      await page.keyboard.press('Escape');
      assert.ok(await manage.evaluate(element => element === document.activeElement));
      assert.equal(await page.getByRole('link', { name: '프로젝트 열기', exact: true }).count(), 0);
      const open = async () => { await manage.click(); await page.getByRole('button', { name: '프로젝트 삭제', exact: true }).click(); };
      await open();
      const dialog = page.getByRole('dialog'), cancel = dialog.getByRole('button', { name: '취소', exact: true });
      const remove = dialog.getByRole('button', { name: '프로젝트 삭제', exact: true });
      await dialog.waitFor();
      assert.ok(await cancel.evaluate(element => element === document.activeElement));
      assert.ok(await remove.isDisabled());
      await page.keyboard.press('Tab');
      assert.ok(await dialog.evaluate(element => element.contains(document.activeElement)));
      await page.keyboard.press('Escape');
      await dialog.waitFor({ state: 'hidden' });
      assert.ok(await manage.evaluate(element => element === document.activeElement));
      assert.equal(requests.length, 0);
      await open();
      const input = dialog.getByLabel('확인을 위해 프로젝트 이름을 입력해 주세요.');
      await input.fill(name + ' '); assert.ok(await remove.isDisabled());
      await input.fill(name);
      await shot('delete-dialog');
      await remove.click();
      await dialog.getByRole('alert').waitFor();
      assert.equal(await rows.count(), 2);
      assert.equal(requests.length, 1);
      await shot('delete-conflict');
      status = 403;
      await remove.click(); await dialog.getByRole('alert').filter({ hasText: '삭제 권한' }).waitFor();
      assert.equal(await rows.count(), 2);
      status = 500;
      await remove.click(); await dialog.getByRole('alert').filter({ hasText: '처리 중 오류' }).waitFor();
      assert.equal(await rows.count(), 2);
      status = 200;
      await remove.click(); await dialog.getByRole('status').waitFor();
      await page.keyboard.press('Escape'); assert.ok(await dialog.isVisible());
      assert.ok(await cancel.isDisabled());
      assert.ok(await dialog.evaluate(element => element === document.activeElement));
      assert.equal(await rows.count(), 2); // no optimistic removal
      assert.equal(requests.length, 4);
      pending();
      await page.getByRole('heading', { name: '내 프로젝트 (1)', exact: true }).waitFor();
      await page.getByRole('status').filter({ hasText: '분석 기록을 삭제했습니다' }).waitFor();
      assert.equal(await rows.count(), 1);
      assert.deepEqual(requests, Array(4).fill(`/api/projects/${first.projectId}`));
      await shot('delete-success');
      data.projects = []; data.projectCount = 0;
      await page.getByRole('button', { name: '새로고침', exact: true }).click();
      await page.getByText('아직 관리 중인 프로젝트가 없습니다.', { exact: true }).waitFor();
      await shot('projects-empty');
      assert.deepEqual(errors, []); assert.deepEqual(external, []);
      checks.push({ width, exactNameGate: true, escapeFocusReturn: true, conflictPreservesRow: true, noOptimisticDeletion: true, duplicateBlocked: true, refreshedCounts: true });
      await page.close();
    }
    console.log(JSON.stringify({ checks, transport: 'MOCK_ONLY', realUserDeletion: false }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
