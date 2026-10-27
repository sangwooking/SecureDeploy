// Actual loopback HTTP boundary checks, owned synthetic accounts and archives only.
const { request } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict'), { execFileSync } = require('node:child_process');
const api = process.env.API_BASE_URL || 'http://127.0.0.1:58033';
const target = new URL(api);
assert.ok(target.protocol === 'http:' && target.hostname === '127.0.0.1' && target.port === '58033');
const archive = entries => execFileSync('python3', ['-c', "import io,sys,json,zipfile\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z:\n for p,s,m in json.load(sys.stdin):\n  i=zipfile.ZipInfo(p);i.external_attr=m<<16;z.writestr(i,s)\nsys.stdout.buffer.write(b.getvalue())"], { input: JSON.stringify(entries) });
const regular = [['application.properties', 'debug=true\n', 0o100644], ['notes.txt', 'static\n', 0o100644]];
(async () => {
  const http = await request.newContext({ baseURL: api }), cases = [], cleanup = [];
  const run = async (method, endpoint, token, data, status = 200) => {
    const r = await http.fetch(endpoint, { method, headers: token ? { Authorization: 'Bearer ' + token } : {}, ...(data === undefined ? {} : { data }) });
    assert.equal(r.status(), status, `${method} ${endpoint}`); return r;
  };
  const signup = async name => (await (await run('POST', '/api/auth/signup', null,
    { email: `${name}-${Date.now()}@example.invalid`, name, password: 'Synthetic-Readiness-33!' })).json()).accessToken;
  const upload = async (token, endpoint, entries, expected = 200) => {
    const r = await http.post(endpoint, { headers: { Authorization: 'Bearer ' + token }, multipart: {
      scanMode: 'STANDARD', file: { name: 'boundary33.zip', mimeType: 'application/zip', buffer: archive(entries) },
    } });
    assert.equal(r.status(), expected, endpoint); return r;
  };
  try {
    const anonymous = await http.post('/api/reviews/upload', { multipart: {
      file: { name: 'anonymous-static.zip', mimeType: 'application/zip', buffer: archive(regular) },
    } });
    assert.equal(anonymous.status(), 401);
    const a = await signup('boundary-A'), b = await signup('boundary-B');
    const source = await (await upload(a, '/api/reviews/upload', regular)).json();
    for (const [name, entries] of [
      ['path-traversal', [['../outside33.txt', 'static', 0o100644]]],
      ['absolute-path', [['/outside33.txt', 'static', 0o100644]]],
      ['duplicate-path', [['same.txt', 'a', 0o100644], ['same.txt', 'b', 0o100644]]],
    ]) { await upload(a, '/api/reviews/upload', entries, 400); cases.push({ name, status: 400, scope: 'INITIAL_UPLOAD' }); }
    const acquire = '/api/editing-workspaces/zip/' + source.reviewId;
    for (const [name, entries] of [
      ['workspace-traversal', [['../outside33.txt', 'static', 0o100644]]],
      ['workspace-reserved-name', [['NUL.txt', 'static', 0o100644]]],
      ['workspace-backslash', [['folder\\file.txt', 'static', 0o100644]]],
      ['workspace-case-collision', [['same.txt', 'a', 0o100644], ['SAME.txt', 'b', 0o100644]]],
      ['workspace-symlink', [['alias', '/outside33.txt', 0o120777]]],
    ]) { await upload(a, acquire, entries, 400); cases.push({ name, status: 400, scope: 'WORKSPACE_ARCHIVE' }); }
    await upload(b, acquire, regular, 403);
    const w = await (await upload(a, acquire, regular)).json(), base = '/api/editing-workspaces/' + w.id;
    cleanup.push([base, a]);
    const otherSource = await (await upload(b, '/api/reviews/upload', regular)).json();
    const other = await (await upload(b, '/api/editing-workspaces/zip/' + otherSource.reviewId, regular)).json();
    cleanup.push(['/api/editing-workspaces/' + other.id, b]);
    const file = w.files.find(f => f.path === 'application.properties'), foreignFile = other.files.find(f => f.path === 'application.properties');
    await run('GET', `${base}/files/${foreignFile.id}`, a, undefined, 404);
    await run('PUT', `${base}/files/${file.id}`, a, { revision: 1, originalHash: '0'.repeat(64), text: 'debug=false\n' }, 409);
    let current = await (await run('PUT', `${base}/files/${file.id}`, a, { revision: 1, originalHash: file.originalHash, text: 'debug=false\n' })).json();
    const note = w.files.find(f => f.path === 'notes.txt');
    current = await (await run('PUT', `${base}/files/${note.id}`, a, { revision: 2, originalHash: note.originalHash, text: 'static updated\n' })).json();
    const valid = { revision: 3, approved: true, changedFileIds: current.changedFileIds };
    for (const [name, invalid] of [
      ['approval-required', { ...valid, approved: false }], ['stale-revision', { ...valid, revision: 2 }],
      ['duplicate-change-list', { ...valid, changedFileIds: [...current.changedFileIds, current.changedFileIds[0]] }],
      ['reordered-change-list', { ...valid, changedFileIds: [...current.changedFileIds].reverse() }],
      ['foreign-change-list', { ...valid, changedFileIds: [foreignFile.id] }], ['null-change-list', { ...valid, changedFileIds: null }],
    ]) {
      await run('POST', base + '/export/patch', a, invalid, 409);
      await run('POST', base + '/scans', a, { ...invalid, externalLookupAcknowledged: true }, 409);
      cases.push({ name, exportStatus: 409, scanStatus: 409 });
    }
    await run('POST', base + '/scans', a, { ...valid, externalLookupAcknowledged: false }, 409);
    const content = await (await run('GET', `${base}/files/${file.id}`, a)).json();
    assert.equal(content.text, 'debug=false\n');
    const provider = await (await run('GET', '/api/editing-workspaces/patch-provider', a)).json();
    assert.equal(provider.available, false);
    const connection = await (await run('GET', '/api/github/connection', a)).json();
    assert.equal(connection.configured, false);
    const cookieOnly = await http.get('/api/workspace', { headers: { Cookie: `accessToken=${a}` } });
    assert.equal(cookieOnly.status(), 401);
    const queryOnly = await http.get('/api/workspace?access_token=' + encodeURIComponent(a)); assert.equal(queryOnly.status(), 401);
    for (const [base, token] of cleanup) { await run('DELETE', base, token); await run('GET', base, token, undefined, 404); }
    console.log(JSON.stringify({ passed: true, cases, foreignFile: 404, wrongHash: 409, userOwnedArchive: 403,
      anonymousAnalysis: 401, cookieAndQueryAreNotAuthentication: 401, githubAppConfigured: false, paidProviderAvailable: false, cleanup: true }));
  } finally {
    for (const [base, token] of cleanup) await http.delete(base, { headers: { Authorization: 'Bearer ' + token } }).catch(() => {});
    await http.dispose();
  }
})().catch(e => { console.error(e.stack); process.exitCode = 1; });
