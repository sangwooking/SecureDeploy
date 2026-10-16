// All API responses are synthetic; no external API, real account or paid AI call.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const workspace = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';
(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const result = require('../result-fixture.cjs')(), errors = [], blocked = [];
      result.serverAnalysis = require('../server-analysis-fixture.cjs')();
      page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-server-analysis-not-authentication');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'AST fixture', email: 'ast@example.invalid' }));
      });
      await page.route('**/*', route => {
        const target = new URL(route.request().url());
        if (!target.pathname.startsWith('/api/')) {
          if (target.origin === new URL(url).origin) return route.continue();
          blocked.push(target.origin); return route.abort();
        }
        const data = target.pathname === '/api/reviews/101' ? result : workspace(target.pathname, result);
        return route.fulfill({ status: data ? 200 : 404, contentType: 'application/json', body: JSON.stringify(data ?? { message: 'Unmocked request' }) });
      });
      await page.goto(`${url}/#/projects/7/findings`);
      const nav = page.getByRole('navigation', { name: '분석 결과 메뉴' });
      await nav.getByRole('button', { name: '결과 요약', exact: true }).click();
      assert.ok((await page.getByRole('region', { name: '서버 코드 흐름 요약' }).innerText()).includes('별도 결과'));
      await nav.getByRole('button', { name: '배포 전 직접 확인할 부분', exact: true }).click();
      const section = page.getByRole('region', { name: '서버 코드 흐름 검사', exact: true });
      assert.ok((await section.innerText()).includes('functions/api/items.ts:3'));
      assert.equal(await section.locator('article').count(), 1);
      for (const title of ['Finding 기술 근거와 한계', '쿼리 값 처리와 방어 근거 (1)', '인증·권한 관련 문맥 (1)', '파일별 구문 검사·추적 범위 (1)']) await section.getByText(title, { exact: true }).click();
      assert.ok((await section.innerText()).includes('접근 권한 취약점으로 판단하지 않습니다'));
      assert.ok((await section.innerText()).includes('functions/api/items.ts:7'));
      assert.ok((await section.innerText()).includes('NOT_COMPARED'));
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow ${width}`);
      assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
      console.log(JSON.stringify({ width, structuralEvidence: 'PASS', boundedCoverage: 'PASS', externalRequests: 0 }));
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(() => { console.error('Server analysis browser assertion failed'); process.exitCode = 1; });
