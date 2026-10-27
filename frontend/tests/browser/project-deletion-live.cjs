// Real isolated H2 API and React UI, synthetic users/projects only. No external services.
const { chromium, request } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const origin = process.env.FRONTEND_URL || 'http://127.0.0.1:5486';
const api = process.env.API_BASE_URL || 'http://127.0.0.1:58036';
for (const address of [origin, api]) {
  const url = new URL(address);
  assert.ok(url.hostname === '127.0.0.1' && !['8080', '5173'].includes(url.port), 'isolated loopback only');
}
const archive = execFileSync('python3', ['-c', "import io,zipfile,sys\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z: z.writestr('application.properties','debug=true\\nserver.error.include-stacktrace=always\\n')\nsys.stdout.buffer.write(b.getvalue())"]);
(async () => {
  const http = await request.newContext({ baseURL: api }), browser = await chromium.launch();
  const expectedDenials = [];
  try {
    const call = async (method, url, token, options = {}, status = 200) => {
      const response = await http.fetch(url, { method, ...options, headers: token ? { Authorization: `Bearer ${token}` } : {} });
      assert.equal(response.status(), status, `${method} ${url}: ${response.status()}`);
      if (status >= 400) expectedDenials.push(status);
      return response;
    };
    const signup = async label => (await call('POST', '/api/auth/signup', null, { data: {
      email: `delete336-${label}-${Date.now()}@example.invalid`, password: 'Synthetic-Deletion-336!', name: label,
    } })).json();
    const a = await signup('A'), b = await signup('B');
    const upload = async (token, name) => (await call('POST', '/api/reviews/upload', token, { multipart: {
      file: { name: name + '.zip', mimeType: 'application/zip', buffer: archive }, scanMode: 'STANDARD',
    } })).json();
    const target = await upload(a.accessToken, 'synthetic-delete336-target');
    const sibling = await upload(a.accessToken, 'synthetic-delete336-sibling');
    const foreign = await upload(b.accessToken, 'synthetic-delete336-foreign');
    const readReview = async (review, token) => (await call('GET', `/api/reviews/${review.reviewId}`, token)).json();
    const siblingBefore = await readReview(sibling, a.accessToken), foreignBefore = await readReview(foreign, b.accessToken);
    const endpoint = `/api/projects/${target.projectId}`;
    await call('DELETE', endpoint, null, {}, 401);
    await call('DELETE', endpoint, b.accessToken, {}, 403);
    await call('DELETE', `/api/reviews/${target.reviewId}`, b.accessToken, {}, 403);
    await call('DELETE', '/api/projects/9223372036854775807', a.accessToken, {}, 404);
    const workspace = await (await call('POST', `/api/editing-workspaces/zip/${target.reviewId}`, a.accessToken, {
      multipart: { file: { name: 'synthetic.zip', mimeType: 'application/zip', buffer: archive } },
    })).json();
    const file = workspace.files.find(item => item.path === 'application.properties');
    const content = await (await call('GET', `/api/editing-workspaces/${workspace.id}/files/${file.id}`, a.accessToken)).json();
    await call('DELETE', `/api/editing-workspaces/${workspace.id}`, b.accessToken, {}, 404);
    await call('DELETE', endpoint, a.accessToken, {}, 409);
    assert.deepEqual(await (await call('GET', `/api/editing-workspaces/${workspace.id}/files/${file.id}`, a.accessToken)).json(), content);
    await call('DELETE', `/api/editing-workspaces/${workspace.id}`, a.accessToken);
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const external = [], errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(session => {
      localStorage.setItem('securedeploy.accessToken', session.accessToken);
      localStorage.setItem('securedeploy.authUser', JSON.stringify(session.user));
    }, a);
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith('/api/')) {
        // Test-only transport proxy; authorization is processed by the actual backend.
        const response = await route.fetch({ url: api + url.pathname + url.search, headers: {
          ...route.request().headers(), origin: 'http://localhost:5173',
        } });
        return route.fulfill({ response, headers: { ...response.headers(), 'access-control-allow-origin': origin } });
      }
      if (url.origin === origin) return route.continue();
      external.push(url.origin); return route.abort();
    });
    await page.goto(origin + '/#/projects');
    await page.getByLabel(`${target.projectName} 관리`, { exact: true }).click();
    await page.getByRole('button', { name: '프로젝트 삭제', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('확인을 위해 프로젝트 이름을 입력해 주세요.').fill(target.projectName);
    await dialog.getByRole('button', { name: '프로젝트 삭제', exact: true }).click();
    await page.getByRole('status').filter({ hasText: '프로젝트와 연결된 분석 기록을 삭제했습니다.' }).waitFor();
    assert.equal(await page.getByRole('heading', { name: '내 프로젝트 (1)', exact: true }).count(), 1);
    await call('GET', endpoint, a.accessToken, {}, 404);
    await call('GET', `/api/reviews/${target.reviewId}`, a.accessToken, {}, 404);
    await call('DELETE', endpoint, a.accessToken, {}, 404);
    await call('GET', `/api/editing-workspaces/${workspace.id}/files/${file.id}`, a.accessToken, {}, 404);
    await call('GET', `/api/editing-workspaces/${workspace.id}/patches`, a.accessToken, {}, 404);
    await call('POST', `/api/editing-workspaces/${workspace.id}/export/zip`, a.accessToken, {
      data: { revision: workspace.revision, changedFileIds: [], approved: true },
    }, 404);
    assert.deepEqual(await readReview(sibling, a.accessToken), siblingBefore);
    assert.deepEqual(await readReview(foreign, b.accessToken), foreignBefore);
    await page.goto(origin + `/#/projects/${target.projectId}/overview`);
    await page.getByRole('alert').filter({ hasText: '프로젝트를 찾을 수 없습니다.' }).waitFor();
    assert.deepEqual(external, []); assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, realH2: true, realReact: true, syntheticOnly: true,
      targetDeleted: true, otherReviewsUnchanged: true, activeWorkspaceRejected: true,
      oldWorkspaceAndExportDenied: true, expectedDenials, proxy: 'TEST_ONLY_ORIGIN_ADAPTER', externalCalls: 0 }));
  } finally { await browser.close(); await http.dispose(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
