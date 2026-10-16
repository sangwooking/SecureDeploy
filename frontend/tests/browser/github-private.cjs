// Fully intercepted GitHub/App/API fixtures. No real credentials or external calls.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const policy = require('../upload-policy-fixture.cjs');
const fixture = require('../result-fixture.cjs');
const workspaceFixture = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5174';

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1100 } });
      const errors = []; page.on('pageerror', e => errors.push(e.message));
      let connected = false, analyzed = false, requests = 0, callbacks = 0, denyRescan = false;
      const result = fixture(); result.sourceType = 'GITHUB'; result.repositoryUrl = 'https://github.com/fixture/private';
      result.sourceMetadata = { owner: 'fixture', repository: 'private', canonicalRepositoryUrl: result.repositoryUrl,
        analyzedBranch: 'develop', commitSha: 'a'.repeat(40), shortCommitSha: 'a'.repeat(7), cloneDepth: 1,
        limitations: [], accessMethod: 'GITHUB_APP', privateRepository: true, repositoryId: 20, installationId: 10 };
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-app-session');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Fixture', email: 'fixture@example.invalid' }));
      });
      await page.route('**/*', async route => {
        const request = route.request(), parsed = new URL(request.url()), path = parsed.pathname;
        if (!path.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
        const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        if (path === '/api/reviews/upload-policy') return json(policy);
        if (path === '/api/github/connection/callback') {
          callbacks++; assert.equal(new URL(page.url()).search, '');
          assert.equal(request.headers().authorization, 'Bearer synthetic-app-session');
          assert.deepEqual(request.postDataJSON(), { code: 'synthetic-code', state: 'synthetic-state' }); connected = true;
          return json({ configured: true, connected, login: 'fixture-owner' });
        }
        if (path === '/api/github/connection') {
          if (request.method() === 'DELETE') { connected = false; return json({ message: '연결을 해제했습니다. 기존 이력은 유지됩니다.' }); }
          return json({ configured: true, connected, reconnectRequired: false, login: connected ? 'fixture-owner' : null,
            installationUrl: 'https://github.com/apps/fixture-app/installations/new' });
        }
        if (path === '/api/github/installations') return json({ installations: [{ installationId: 10, account: 'fixture-owner' }], hasNextPage: false });
        if (path === '/api/github/installations/10/repositories') return json({ repositories: [{ repositoryId: 20, installationId: 10,
          name: 'private', fullName: 'fixture/private', repositoryUrl: result.repositoryUrl, privateRepository: true, defaultBranch: 'develop' }], hasNextPage: false });
        if (path === '/api/reviews/github/connected') {
          requests++; assert.equal(request.postDataJSON().scanMode, 'STANDARD');
          assert.equal(request.postDataJSON().repositoryId, 20); analyzed = true; return json(result);
        }
        if (path === '/api/projects/7/reviews/github') {
          requests++; assert.ok(denyRescan); return json({ message: '선택한 저장소에 접근할 수 없습니다. GitHub 연결을 다시 확인해 주세요.' }, 403);
        }
        if (path === '/api/workspace' && !analyzed) return json({ projectCount: 0, projects: [] });
        const data = workspaceFixture(path, result);
        if (path === '/api/projects/7') return json({ ...data, sourceType: 'GITHUB', repositoryUrl: result.repositoryUrl, githubRepositoryId: 20, githubInstallationId: 10, privateRepository: true });
        if (data) return json(data);
        if (path === `/api/reviews/${result.reviewId}`) return json(result);
        return json({ message: 'Offline fixture endpoint unavailable' }, 404);
      });
      await page.goto(`${url}/?code=synthetic-code&state=synthetic-state`);
      await page.getByText('GitHub 계정이 연결되었습니다. 분석할 저장소를 선택해 주세요.', { exact: true }).waitFor();
      assert.equal(callbacks, 1); assert.equal(new URL(page.url()).search, '');
      await page.getByRole('button', { name: '계정으로 돌아가기' }).click();
      await page.getByText('fixture-owner', { exact: true }).waitFor();
      await page.getByRole('navigation', { name: '앱 메뉴' }).getByRole('link', { name: '새 프로젝트', exact: true }).click();
      await page.getByRole('button', { name: '연결된 GitHub 저장소', exact: true }).click();
      await page.getByLabel('App 설치 계정').selectOption('10');
      await page.getByLabel('접근 가능한 저장소').selectOption('20');
      await page.getByText(/읽기 권한 확인됨/).waitFor();
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/github-private-${width}.png`, fullPage: true });
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      await page.getByText('비공개 저장소 · GitHub App 읽기 전용 · 분석 시점 기준', { exact: true }).waitFor();
      assert.equal(requests, 1);
      denyRescan = true;
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).getByRole('link', { name: '재검사', exact: true }).click();
      await page.getByRole('button', { name: '대상 확인 후 다시 검사' }).click();
      await page.getByRole('alert').filter({ hasText: '선택한 저장소에 접근할 수 없습니다' }).waitFor();
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).getByRole('link', { name: '분석 이력', exact: true }).click();
      await page.getByRole('heading', { name: /분석 이력/ }).waitFor();
      await page.getByRole('navigation', { name: '앱 메뉴' }).getByRole('link', { name: '계정', exact: true }).click();
      page.once('dialog', dialog => dialog.accept());
      await page.getByRole('button', { name: '연결 해제', exact: true }).click();
      await page.getByRole('button', { name: 'GitHub 연결', exact: true }).waitFor();
      const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
      assert.ok(!stored.includes('synthetic-code') && !stored.includes('synthetic-state') && !stored.includes('ghu_'));
      assert.deepEqual(errors, []); await page.close();
    }
    for (const failure of [
      { status: 503, message: 'GitHub App 인증 설정을 확인해야 합니다. 관리자에게 문의해 주세요.' },
      { status: 400, message: 'GitHub 승인 코드를 확인하지 못했습니다. 계정에서 연결을 다시 시작해 주세요.' },
      { status: 502, message: 'GitHub 연결 인증을 완료하지 못했습니다. 계정에서 다시 연결해 주세요.' },
    ]) {
      const page = await browser.newPage();
      let callbacks = 0;
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-app-session');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Fixture', email: 'fixture@example.invalid' }));
      });
      await page.route('**/*', async route => {
        const request = route.request(), parsed = new URL(request.url());
        if (parsed.pathname === '/api/github/connection/callback') {
          callbacks++;
          assert.equal(request.headers().authorization, 'Bearer synthetic-app-session');
          assert.equal(new URL(page.url()).search, '');
          return route.fulfill({ status: failure.status, contentType: 'application/json', body: JSON.stringify({ message: failure.message }) });
        }
        if (parsed.pathname.startsWith('/api/')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
        return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
      });
      await page.goto(`${url}/?code=synthetic-code&state=synthetic-state`);
      await page.getByRole('status').filter({ hasText: failure.message }).waitFor();
      assert.equal(callbacks, 1);
      assert.ok(!(await page.locator('body').innerText()).includes('GitHub 인증이 만료되었거나 해제되었습니다'));
      assert.equal(await page.evaluate(() => localStorage.getItem('securedeploy.accessToken')), 'synthetic-app-session');
      const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
      assert.ok(!stored.includes('synthetic-code') && !stored.includes('synthetic-state'));
      await page.close();
    }
    console.log(JSON.stringify({ passed: true, widths: [1440, 390, 320], callbackRequests: 1, standard: true,
      privateSelection: true, revokedRescanFails: true, historyPreserved: true, callbackErrors: 3, jwtForwarded: true, externalCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
