// Real loopback application/H2/worker. No GitHub, model, or target-code execution.
const { chromium, request } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { stage, pane } = require('./editor-navigation.cjs');
const origin = process.env.FRONTEND_URL || 'http://127.0.0.1:5484';
const api = process.env.API_BASE_URL || 'http://127.0.0.1:58033';
for (const value of [origin, api]) {
  const u = new URL(value);
  assert.ok(u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname) && !['8080', '5173'].includes(u.port), 'isolated loopback only');
}
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const original = 'debug=true\nserver.error.include-stacktrace=always\n';
const edited = 'debug=false\nserver.error.include-stacktrace=never\n';
const files = {
  'application.properties': Buffer.from(original),
  'supabase/functions/inspect/index.ts': Buffer.from("Deno.serve(async request => {\n  return Response.json({status: 'ok', diagnostic: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')}, {status: 201});\n});\n"),
  'assets/example.bin': Buffer.from([0, 255, 2]),
  'notes/line-endings.txt': Buffer.from('\ufeffstatic\r\nno final newline'),
  'static/example.html': Buffer.from('<script>window.__sourceExecuted=true</script>'),
  'package.json': Buffer.from(JSON.stringify({ name: 'synthetic-readiness-only', private: true, devDependencies: { undici: '7.29.1' } })),
  'package-lock.json': Buffer.from(JSON.stringify({ name: 'synthetic-readiness-only', lockfileVersion: 3, packages: {
    '': { devDependencies: { undici: '7.29.1' } }, 'node_modules/undici': { version: '7.29.1', dev: true },
  } })),
};
function zip(entries) {
  return execFileSync('python3', ['-c', "import sys,json,io,zipfile,base64\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:\n for p,v in json.load(sys.stdin):\n  i=zipfile.ZipInfo(p);i.external_attr=0o100644<<16;z.writestr(i,base64.b64decode(v))\nsys.stdout.buffer.write(b.getvalue())"],
    { input: JSON.stringify(entries.map(([p, b]) => [p, b.toString('base64')])) });
}
const archive = zip(Object.entries(files));
function extract(bytes) {
  return JSON.parse(execFileSync('python3', ['-c', "import sys,io,zipfile,json,base64\nwith zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as z: print(json.dumps([{'path':i.filename,'mode':i.external_attr>>16,'directory':i.is_dir(),'base64':base64.b64encode(z.read(i)).decode()} for i in z.infolist()]))"], { input: bytes }).toString());
}
function inputHash(entries) {
  return sha(Buffer.from(entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
    .map(e => `${e.path}\0${e.directory}\0${e.mode}\0${sha(Buffer.from(e.base64, 'base64'))}\n`).join('')));
}
function expiredToken(user) {
  const enc = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const body = `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({ sub: String(user), exp: Math.floor(Date.now() / 1000) - 60 })}`;
  return body + '.' + crypto.createHmac('sha256', 'readiness33-synthetic-isolated-signing-key-only-0001').update(body).digest('base64url');
}
(async () => {
  const browser = await chromium.launch(), http = await request.newContext({ baseURL: api });
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'securedeploy-product33-'));
  const report = { sourceCommit: execFileSync('git', ['rev-parse', 'HEAD']).toString().trim(), worker: 'ts-server-v40',
    api, origin, uploadZipSha256: sha(archive), githubApp: 'BLOCKED_BY_USER_DECISION', paidAI: false, runs: [], negative: [], authentication: {} };
  const temporaryWorkspaces = [];
  try {
    const call = async (method, endpoint, token, body, expected = 200) => {
      const response = await http.fetch(endpoint, { method, headers: token ? { Authorization: `Bearer ${token}` } : {}, ...(body === undefined ? {} : { data: body }) });
      assert.equal(response.status(), expected, `${method} ${endpoint}: ${response.status()}`);
      if (expected >= 400) report.negative.push({ method, expected, actual: response.status() });
      return response;
    };
    const unauth = await call('GET', '/api/workspace', null, undefined, 401);
    assert.ok(!(await unauth.text()).includes('java.'));
    const allowedCors = await http.fetch('/api/auth/login', { method: 'OPTIONS', headers: { Origin: 'http://localhost:5173', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,authorization' } });
    assert.equal(allowedCors.status(), 200);
    assert.equal(allowedCors.headers()['access-control-allow-origin'], 'http://localhost:5173');
    const deniedCors = await http.fetch('/api/auth/login', { method: 'OPTIONS', headers: { Origin: 'https://untrusted.example.invalid', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(deniedCors.status(), 403);
    report.authentication.cors = { configuredOrigin: 200, untrustedOrigin: 403, production: 'NOT_VERIFIED' };
    for (const width of [1440, 1280, 768, 390, 320]) {
      const context = await browser.newContext({ viewport: { width, height: 1000 }, acceptDownloads: true });
      const page = await context.newPage(), errors = [], outbound = [];
      page.on('pageerror', e => errors.push(e.message));
      await context.route('**/*', route => {
        const u = new URL(route.request().url());
        if (u.origin === origin) return route.continue();
        outbound.push(u.origin); return route.abort();
      });
      const email = `product33-${width}-${Date.now()}@example.invalid`;
      await page.goto(origin);
      assert.equal(await page.evaluate(() => localStorage.length), 0);
      await page.getByRole('button', { name: '회원가입', exact: true }).click();
      await page.getByLabel('이름', { exact: true }).fill('Readiness synthetic A');
      await page.getByLabel('이메일', { exact: true }).fill(email);
      await page.getByLabel('비밀번호', { exact: true }).fill('Synthetic-Readiness-33!');
      const signup = page.waitForResponse(r => r.url().endsWith('/api/auth/signup'));
      await page.locator('.auth-submit').click();
      const signupResponse = await signup; assert.equal(signupResponse.status(), 200);
      assert.ok(!signupResponse.headers()['set-cookie']);
      const a = await signupResponse.json(), token = a.accessToken;
      await page.getByRole('navigation', { name: '앱 메뉴' }).waitFor();
      assert.deepEqual(await context.cookies(), []);
      const b = await (await call('POST', '/api/auth/signup', null, { email: 'b-' + email, name: 'Readiness synthetic B', password: 'Synthetic-Readiness-33!' })).json();
      await call('GET', '/api/workspace', expiredToken(a.user.id), undefined, 401);
      await call('GET', '/api/workspace', 'invalid.readiness.token', undefined, 401);
      await page.getByRole('link', { name: '새 프로젝트', exact: true }).click();
      await page.getByLabel('ZIP 파일 선택').setInputFiles({ name: 'readiness-static-only.zip', mimeType: 'application/zip', buffer: archive });
      const upload = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/api/reviews/upload'));
      await page.getByRole('button', { name: '분석 시작', exact: true }).click();
      const uploaded = await upload; assert.equal(uploaded.status(), 200);
      const before = await uploaded.json();
      assert.equal(before.serverAnalysis.analyzerVersion, 'ts-server-v40');
      assert.ok(before.vulnerabilities.some(v => v.ruleId === 'DEBUG_ENABLED'));
      assert.ok(before.serverAnalysis.validatedFindings.some(f => f.ruleId === 'TS_SENSITIVE_DATA_EXPOSURE'));
      const direct = JSON.parse(execFileSync(process.execPath, ['../analyzers/typescript/worker.mjs'], { input: JSON.stringify({ files:
        Object.entries(files).filter(([p]) => /\.(?:ts|js)$/.test(p)).map(([filePath, value]) => ({ filePath, content: value.toString('utf8') })) }) }));
      const directFlow = direct.findings.find(f => f.ruleId === 'TS_SENSITIVE_DATA_EXPOSURE');
      const persistedFlow = before.serverAnalysis.validatedFindings.find(f => f.ruleId === 'TS_SENSITIVE_DATA_EXPOSURE');
      assert.ok(directFlow); assert.deepEqual(persistedFlow.location, directFlow.sink);
      assert.ok(persistedFlow.evidence.length > 0); assert.ok(persistedFlow.evidence.some(e => e.source && e.flow.length > 0));
      await page.locator('.summary-facts').waitFor();
      const displayed = await page.locator('.summary-facts').innerText();
      assert.ok(displayed.includes(`${before.securityScore} / 100`));
      assert.ok(displayed.includes(before.riskAssessment.prioritizedDeploymentAssessment));
      assert.ok(displayed.includes(before.coverage.status));
      assert.equal(await page.evaluate(() => window.__sourceExecuted), undefined);
      await page.locator('.report-menu > summary').click();
      const pdfDownloading = page.waitForEvent('download');
      await page.getByRole('button', { name: '기본 리포트 다운로드', exact: true }).click();
      const pdfFile = path.join(output, `report-${width}.pdf`);
      await (await pdfDownloading).saveAs(pdfFile);
      assert.equal(fs.readFileSync(pdfFile).subarray(0, 5).toString(), '%PDF-');
      const facts = { width, originalReview: before.reviewId, score: before.securityScore, risk: before.riskAssessment.prioritizedDeploymentAssessment,
        coverage: before.coverage.status, sca: { status: before.sca.status, analyzedAt: before.sca.analyzedAt,
          packageVersions: before.sca.summary.vulnerableDependencies, impacts: before.sca.summary.dependencyVulnerabilities },
        inputFileHashes: Object.fromEntries(Object.entries(files).map(([p, value]) => [p, sha(value)])) };
      facts.sourceSinkRetained = { ruleId: persistedFlow.ruleId, location: persistedFlow.location, comparison: persistedFlow.comparisonPolicy,
        evidence: persistedFlow.evidence.map(e => ({ source: e.source, sink: e.sink, flow: e.flow })) };
      for (const suffix of ['', '/reviews', '/dashboard', '/reviews/compare-latest']) await call('GET', `/api/projects/${before.projectId}${suffix}`, b.accessToken, undefined, 403);
      for (const suffix of ['', '/report', '/report/ai']) await call('GET', `/api/reviews/${before.reviewId}${suffix}`, b.accessToken, undefined, 403);
      await page.getByRole('button', { name: '수정 작업 공간 열기', exact: true }).click();
      await page.getByLabel('원본 ZIP', { exact: true }).setInputFiles({ name: 'readiness-static-only.zip', mimeType: 'application/zip', buffer: archive });
      const acquiring = page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes(`/zip/${before.reviewId}`));
      await page.getByRole('button', { name: '원본 확보 후 작업 공간 시작' }).click();
      const w = await (await acquiring).json(), base = '/api/editing-workspaces/' + w.id;
      temporaryWorkspaces.push({ base, token });
      assert.equal(w.identityStatus, 'UNVERIFIED_REUPLOAD');
      const file = w.files.find(f => f.path === 'application.properties'), flowFile = w.files.find(f => f.path.endsWith('/inspect/index.ts'));
      const beforeContent = await (await call('GET', `${base}/files/${file.id}`, token)).json();
      assert.equal(beforeContent.currentHash, sha(Buffer.from(original)));
      await pane(page, '파일');
      await page.getByRole('button', { name: 'example.html', exact: true }).click();
      assert.equal(await page.locator('#source-code').inputValue(), files['static/example.html'].toString('utf8'));
      assert.equal(await page.locator('.source-edit-pane script').count(), 0);
      assert.equal(await page.evaluate(() => window.__sourceExecuted), undefined);
      for (const endpoint of [base, `${base}/files/${file.id}`, `${base}/files/${file.id}/diff`, `${base}/patches`, `${base}/patches/not-owned`])
        await call('GET', endpoint, b.accessToken, undefined, 404);
      for (const [method, endpoint, data] of [
        ['PUT', `${base}/files/${file.id}`, { revision: 1, originalHash: file.originalHash, text: edited }],
        ['POST', `${base}/files/${file.id}/revert`, { revision: 1, originalHash: file.originalHash }],
        ['POST', `${base}/export/patch`, { revision: 1, changedFileIds: [], approved: true }],
        ['POST', `${base}/scans`, { revision: 1, changedFileIds: [], approved: true, externalLookupAcknowledged: true }],
        ['POST', `${base}/deterministic-patches`, { fileId: flowFile.id, findingId: 0, flowFindingId: before.serverAnalysis.validatedFindings[0].findingId, revision: 1, originalHash: flowFile.originalHash, currentHash: flowFile.originalHash }],
        ['POST', `${base}/patches/not-owned/apply`, { revision: 1, currentHash: file.originalHash, approved: true }],
        ['POST', `${base}/patches/not-owned/reject`, {}], ['DELETE', base, undefined],
      ]) await call(method, endpoint, b.accessToken, data, 404);
      await pane(page, '파일'); await page.getByRole('button', { name: 'application.properties', exact: true }).click();
      await page.locator('#source-code').fill(edited);
      const saving = page.waitForResponse(r => r.request().method() === 'PUT' && r.url().includes(`/files/${file.id}`));
      await page.getByRole('button', { name: '변경 저장', exact: true }).click();
      const current = await (await saving).json(); assert.equal(current.revision, 2);
      const approval = { revision: 2, changedFileIds: current.changedFileIds, approved: true };
      await call('PUT', `${base}/files/${file.id}`, token, { revision: 1, originalHash: file.originalHash, text: original }, 409);
      for (const invalid of [{ ...approval, approved: false }, { ...approval, revision: 1 }, { ...approval, changedFileIds: [] }, { ...approval, changedFileIds: [...current.changedFileIds, ...current.changedFileIds] }])
        await call('POST', `${base}/export/patch`, token, invalid, 409);
      await stage(page, '변경 검토 · 다운로드');
      await page.getByRole('button', { name: '전체 변경 Diff 확인' }).click();
      assert.equal(await page.getByRole('button', { name: 'Patch 다운로드', exact: true }).isDisabled(), true);
      await page.locator('.source-export-approval input').check();
      const downloading = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Patch 다운로드', exact: true }).click();
      const download = await downloading, patchFile = path.join(output, `accepted-${width}.patch`);
      await download.saveAs(patchFile);
      const patch = fs.readFileSync(patchFile, 'utf8');
      assert.ok(patch.includes('-debug=true')); assert.ok(patch.includes('+debug=false')); assert.ok(!patch.includes('diagnostic:'));
      const patchRoot = fs.mkdtempSync(path.join(output, 'patch-check-'));
      fs.writeFileSync(path.join(patchRoot, 'application.properties'), original);
      execFileSync('git', ['apply', '--check', patchFile], { cwd: patchRoot });
      execFileSync('git', ['apply', patchFile], { cwd: patchRoot });
      assert.equal(fs.readFileSync(path.join(patchRoot, 'application.properties'), 'utf8'), edited);
      const exported = await call('POST', `${base}/export/zip`, token, approval);
      assert.ok(exported.headers()['cache-control'].includes('no-store'));
      assert.equal(exported.headers()['x-content-type-options'], 'nosniff');
      const exportedEntries = extract(await exported.body());
      for (const e of exportedEntries) assert.equal(sha(Buffer.from(e.base64, 'base64')), sha(e.path === 'application.properties' ? Buffer.from(edited) : files[e.path]));
      await stage(page, '재검사 · 비교');
      const scan = page.getByLabel('수정본 보안 재검사', { exact: true });
      await scan.getByRole('checkbox').check();
      const starting = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/scans'));
      await scan.getByRole('button', { name: '수정본 다시 검사', exact: true }).click();
      const job = await (await starting).json();
      const repeat = await (await call('POST', base + '/scans', token, { ...approval, externalLookupAcknowledged: true }, 202)).json();
      assert.equal(repeat.id, job.id);
      await call('GET', '/api/editing-workspaces/scans/' + job.id, b.accessToken, undefined, 404);
      await scan.getByRole('link', { name: '저장된 수정본 결과와 History 열기' }).waitFor({ timeout: 60000 });
      const completed = await (await call('GET', '/api/editing-workspaces/scans/' + job.id, token)).json();
      const after = await (await call('GET', '/api/reviews/' + completed.reviewId, token)).json();
      assert.equal(completed.inputHash, inputHash(exportedEntries));
      assert.equal(after.workspaceScan.inputHash, completed.inputHash); assert.equal(after.workspaceScan.revision, 2);
      assert.equal(after.workspaceScan.baselineVerified, false); assert.equal(after.comparison.status, 'NO_BASELINE');
      assert.equal(after.comparison.counts.RESOLVED, 0);
      assert.ok(!after.vulnerabilities.some(v => v.ruleId === 'DEBUG_ENABLED'));
      assert.ok(after.serverAnalysis.validatedFindings.some(f => f.ruleId === 'TS_SENSITIVE_DATA_EXPOSURE'));
      for (const entry of after.workspaceScan.files) assert.equal(entry.currentHash, sha(entry.path === 'application.properties' ? Buffer.from(edited) : files[entry.path]));
      assert.deepEqual(await (await call('GET', '/api/reviews/' + before.reviewId, token)).json(), before);
      await call('GET', '/api/reviews/' + after.reviewId, b.accessToken, undefined, 403);
      const activePane = page.getByLabel('수정본 보안 재검사', { exact: true });
      await activePane.screenshot({ path: path.join(output, `comparison-${width}.png`) });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      if (width === 1440) {
        await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await page.getByRole('button', { name: '작업 공간 삭제', exact: true }).focus();
        assert.ok(await page.getByRole('button', { name: '작업 공간 삭제', exact: true }).evaluate(e => e === document.activeElement));
        await page.evaluate(() => { document.documentElement.style.zoom = ''; });
      }
      page.once('dialog', d => d.accept()); await page.getByRole('button', { name: '작업 공간 삭제', exact: true }).click();
      await page.getByRole('button', { name: '원본 확보 후 작업 공간 시작' }).waitFor();
      await call('GET', base, token, undefined, 404);
      assert.equal((await (await call('GET', '/api/reviews/' + after.reviewId, token)).json()).reviewId, after.reviewId);
      await page.goto(`${origin}/#/projects/${after.projectId}/history`);
      await page.getByRole('heading', { name: /^분석 이력 \(/ }).waitFor();
      await page.locator('.history-item').first().click();
      await page.locator('.summary-facts').waitFor();
      const afterVisible = await page.locator('.summary-facts').innerText();
      assert.ok(afterVisible.includes('100 / 100')); assert.ok(afterVisible.includes(after.coverage.status));
      assert.ok(afterVisible.includes(after.riskAssessment.prioritizedDeploymentAssessment));
      await page.getByRole('button', { name: '로그아웃', exact: true }).click();
      assert.equal(await page.evaluate(() => localStorage.getItem('securedeploy.accessToken')), null);
      // Product uses stateless bearer tokens: logout removes browser state, not a server revocation list.
      await call('GET', '/api/workspace', token);
      report.authentication.logout = { browserCleared: true, copiedTokenStillValid: true, revocation: 'NOT_IMPLEMENTED_STATELESS' };
      facts.after = { reviewId: after.reviewId, score: after.securityScore, risk: after.riskAssessment.prioritizedDeploymentAssessment,
        coverage: after.coverage.status, comparison: after.comparison.status, resolved: after.comparison.counts.RESOLVED,
        revision: after.workspaceScan.revision, inputHash: after.workspaceScan.inputHash, approvedPatchSha256: sha(Buffer.from(patch)),
        appliedPatchFileSha256: sha(fs.readFileSync(path.join(patchRoot, 'application.properties'))) };
      assert.deepEqual(errors, []); assert.deepEqual(outbound, []);
      report.runs.push(facts); await context.close();
    }
    const expiredContext = await browser.newContext();
    const expiredPage = await expiredContext.newPage();
    await expiredPage.addInitScript(token => {
      localStorage.setItem('securedeploy.accessToken', token);
      localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Expired synthetic', email: 'expired@example.invalid' }));
    }, expiredToken(1));
    await expiredPage.goto(origin);
    await expiredPage.getByRole('alert').filter({ hasText: '만료되었습니다' }).waitFor();
    assert.ok(await expiredPage.evaluate(() => !!localStorage.getItem('securedeploy.accessToken')));
    await expiredPage.getByRole('button', { name: '로그아웃', exact: true }).click();
    assert.equal(await expiredPage.evaluate(() => localStorage.getItem('securedeploy.accessToken')), null);
    report.authentication.expiredBrowserRecovery = 'ERROR_THEN_EXPLICIT_LOGOUT_NO_AUTOMATIC_REDIRECT';
    await expiredContext.close();
    fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
    console.log(JSON.stringify({ passed: true, widths: report.runs.map(r => r.width), worker: report.worker,
      realH2: true, githubApp: report.githubApp, paidAI: false, negativeChecks: report.negative.length,
      expiredRecovery: report.authentication.expiredBrowserRecovery, proofDirectory: output, runs: report.runs.map(r => ({ width: r.width, sca: r.sca, score: r.score, after: r.after })) }));
  } finally {
    for (const { base, token } of temporaryWorkspaces) await http.delete(base, { headers: { Authorization: `Bearer ${token}` } }).catch(() => {});
    await browser.close(); await http.dispose();
    // Keep source-free receipts/screenshots, not temporary source copies or downloads.
    for (const entry of fs.readdirSync(output)) if (/^(?:patch-check-|accepted-|report-)/.test(entry))
      fs.rmSync(path.join(output, entry), { recursive: true, force: true });
  }
})().catch(e => { console.error(e.stack); process.exitCode = 1; });
