// Run against Vite with Playwright installed, or set PLAYWRIGHT_MODULE to its module path.
// No request reaches a backend or external API. All credentials and responses are synthetic.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fixture = require('../result-fixture.cjs');
const workspaceFixture = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const result = fixture(), calls = [], errors = [];
  let scenario = 'normal';
  const responseFixture = () => {
    const copy = structuredClone(result);
    if (scenario === 'disabled') copy.semanticReview = { ...copy.semanticReview, semanticReviewStatus: 'NOT_REQUESTED',
      candidates: [], requestCount: 0, semanticSlicesAnalyzed: 0, provider: 'template', model: null, usage: null };
    if (scenario === 'empty') copy.semanticReview.candidates = [];
    if (scenario === 'legacy') { copy.riskAssessment = null; copy.sca = null; copy.remediation = null; copy.semanticReview = null; copy.scanMode = null; }
    return copy;
  };
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      const request = route.request(), parsed = new URL(request.url()), path = parsed.pathname;
      if (!path.startsWith('/api/')) {
        return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
      }
      calls.push({ path, method: request.method() });
      const json = data => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(data) });
      const workspace = workspaceFixture(path, responseFixture());
      if (workspace) return json(workspace);
      if (path === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
      if (path === '/api/auth/login') return json({ accessToken: 'ui-fixture-not-a-real-token', tokenType: 'Bearer',
        user: { id: 1, email: 'ui@example.invalid', name: '테스트 사용자' } });
      if (path === '/api/reviews' && request.method() === 'GET') return json([{ ...result, sourceType: 'ZIP', createdAt: '2026-10-12T00:00:00Z' }]);
      if (path === '/api/reviews/101') return json(responseFixture());
      if (path === '/api/reviews/upload' || path === '/api/reviews/github') {
        const enhanced = request.postData()?.includes('AI_ENHANCED');
        assert.equal(enhanced, path === '/api/reviews/github', 'ZIP defaults to STANDARD; GitHub uses the explicit AI opt-in');
        const data = responseFixture();
        if (!enhanced) { data.scanMode = 'STANDARD'; data.semanticReview = { ...data.semanticReview, scanMode: 'STANDARD',
          semanticReviewStatus: 'NOT_REQUESTED', candidates: [], semanticSlicesAnalyzed: 0, requestCount: 0 }; }
        await new Promise(resolve => setTimeout(resolve, 120));
        return json(data);
      }
      if (path === '/api/vulnerabilities/51/status') {
        const payload = request.postDataJSON();
        result.vulnerabilities[0].status = payload.status;
        result.vulnerabilities[0].statusComment = payload.comment;
        return json(result.vulnerabilities[0]);
      }
      if (path === '/api/reviews/101/report' || path === '/api/reviews/101/report/ai') return route.fulfill({ status: 200, contentType: 'application/pdf', body: '%PDF-1.4\n% mock download fixture' });
      return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ message: 'Mock route missing' }) });
    });
    await page.goto(url);
    await page.getByLabel('이메일', { exact: true }).fill('ui@example.invalid');
    await page.getByLabel('비밀번호', { exact: true }).fill('fake-ui-test-password');
    await page.locator('.auth-submit').click();
    await page.getByRole('link', { name: '프로젝트 열기', exact: true }).click();
    await page.getByRole('navigation', { name: '프로젝트 메뉴' }).getByRole('link', { name: '발견된 문제', exact: true }).click();
    const navigate = async name => {
      await page.getByRole('navigation', { name: '분석 결과 메뉴' }).getByRole('button', { name, exact: true }).click();
      await page.waitForTimeout(60);
    };
    const visible = () => page.locator('#result-content').innerText();
    const openDetails = async selector => {
      const element = page.locator(selector);
      if (!(await element.evaluate(el => el.open))) await element.locator(':scope > summary').click();
    };
    await navigate('결과 요약');
    assert.ok((await visible()).includes('배포 전 수정 필요'));
    for (const word of ['CVE-', 'HARDCODED_SECRET', 'fixture-model', 'Confidence']) assert.ok(!(await visible()).includes(word));
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844], ['small-mobile', 320, 740]]) {
      await page.setViewportSize({ width, height });
      await navigate('결과 요약');
      for (const section of ['결과 요약', '반드시 처리', '배포 전 직접 확인할 부분', '수정 권장', '해결 방법', '기술 정보']) {
        await navigate(section);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), name + ': ' + section + ' overflow');
        if (section === '반드시 처리') {
          const card = page.locator('.action-finding').first();
          assert.ok(!(await visible()).includes('Confidence'));
          assert.ok(!(await visible()).includes('Config.java'));
          await card.locator('.finding-remediation > summary').click();
          for (const text of ['템플릿 가이드', '어떤 일이 생길 수 있나요?', '비용 발생', '무엇을 수정해야 하나요?', '수정 후 무엇을 확인하나요?']) assert.ok((await visible()).includes(text), text);
          assert.ok(!(await visible()).includes('fixture-model'));
          await page.screenshot({ path: `/private/tmp/securedeploy-ai-guide-${name}.png`, fullPage: true });
          await card.locator('.finding-remediation > summary').click();
          await card.locator(':scope > .technical-details > summary').click();
          assert.ok((await visible()).includes('secret = <redacted>'));
          await card.locator(':scope > .technical-details > summary').click();
          await page.getByLabel('심각도', { exact: false }).selectOption('LOW');
          assert.ok((await visible()).includes('선택한 심각도'));
          await page.getByLabel('심각도', { exact: false }).selectOption('ALL');
        }
        if (section === '배포 전 직접 확인할 부분') {
          assert.equal(await page.locator('.semantic-candidate').count(), 1);
          assert.ok(!(await visible()).includes('IDOR'));
          for (const word of ['Controller', '소유자', 'findAccount']) assert.ok(!(await visible()).includes(word), word);
          for (const text of ['테스트 계정 A와 B', '접근이 거부되는지', '안전하다는 뜻이 아닙니다', '잠금 파일', '조회 실패']) assert.ok((await visible()).includes(text), text);
          await page.locator('.semantic-candidate .technical-details > summary').click();
          assert.ok((await visible()).includes('AI_SECURITY_CANDIDATE'));
          await page.locator('.semantic-candidate .technical-details > summary').click();
        }
        if (section === '수정 권장') {
          assert.ok((await visible()).includes('알려진 수정 버전'));
          assert.ok(!(await visible()).includes('CVE-2099'));
          await page.getByText('업데이트 방법 보기', { exact: true }).click();
          assert.ok((await visible()).includes('호환성을 보장하지 않습니다'));
        }
        if (['결과 요약', '반드시 처리', '배포 전 직접 확인할 부분'].includes(section)) {
          await page.screenshot({ path: `/private/tmp/securedeploy-result-${name}-${['결과 요약', '반드시 처리', '배포 전 직접 확인할 부분'].indexOf(section)}.png`, fullPage: true });
        }
      }
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await navigate('반드시 처리');
    await page.getByText('진행 상태와 메모', { exact: true }).click();
    await page.getByLabel('메모', { exact: true }).fill('테스트 메모');
    const statusSaved = page.waitForResponse(response => response.url().endsWith('/api/vulnerabilities/51/status'));
    await page.getByLabel('상태', { exact: true }).selectOption('IN_PROGRESS');
    await statusSaved;
    await page.locator('.action-finding .status-badge').getByText('수정 중', { exact: true }).waitFor();
    await navigate('결과 요약');
    assert.ok((await visible()).includes('배포 전 수정 필요'));
    await page.locator('.report-menu > summary').click();
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: '기본 리포트 다운로드', exact: true }).click();
    assert.equal((await download).suggestedFilename(), 'securedeploy-report-101.pdf');
    page.once('dialog', async dialog => { assert.ok(dialog.message().includes('비용')); await dialog.dismiss(); });
    await page.getByRole('button', { name: 'AI 리뷰 PDF 생성·다운로드', exact: true }).click();
    assert.ok(!calls.some(call => call.path.endsWith('/report/ai')));
    page.once('dialog', dialog => dialog.accept());
    const aiDownload = page.waitForEvent('download');
    await page.getByRole('button', { name: 'AI 리뷰 PDF 생성·다운로드', exact: true }).click();
    assert.equal((await aiDownload).suggestedFilename(), 'securedeploy-ai-report-101.pdf');
    await navigate('해결 방법');
    assert.ok((await visible()).includes('코드에서 인증정보 제거'));
    assert.equal(await page.locator('.ai-subtab').count(), 0);
    await page.getByLabel('해결할 문제 선택').selectOption('coverage:sca');
    assert.ok(!(await visible()).includes('코드에서 인증정보 제거'));
    assert.ok((await visible()).includes('기본 안내'));
    assert.ok((await visible()).includes('안전하다는 뜻이 아닙니다'));
    await page.getByLabel('해결할 문제 선택').selectOption('code:51');
    assert.ok((await visible()).includes('코드에서 인증정보 제거'));
    for (const current of ['disabled', 'empty', 'legacy']) {
      scenario = current;
      await page.getByRole('navigation', { name: '프로젝트 메뉴' }).getByRole('link', { name: '분석 이력', exact: true }).click();
      await page.locator('.history-item').click();
      await page.waitForTimeout(100);
      await page.reload();
      await navigate('결과 요약');
      if (current === 'disabled') assert.ok((await visible()).includes('외부 AI 분석이 비활성화'));
      if (current === 'legacy') assert.ok((await visible()).includes('미평가'));
      await navigate('배포 전 직접 확인할 부분');
      if (current === 'empty') assert.ok((await visible()).includes('후보 0건은 안전을 의미하지 않습니다'));
      if (current === 'legacy') assert.ok((await visible()).includes('우선순위가 저장되지 않은 코드 문제'));
    }
    scenario = 'normal';
    await page.getByRole('navigation', { name: '앱 메뉴' }).getByRole('link', { name: '새 프로젝트', exact: true }).click();
    const checkbox = page.getByRole('checkbox');
    assert.equal(await checkbox.isChecked(), false);
    await page.locator('input[type=file]').setInputFiles({ name: 'ui-fixture.zip', mimeType: 'application/zip', buffer: Buffer.from('not sent to backend') });
    await page.getByRole('button', { name: '분석 시작', exact: true }).click();
    // The project overview is the destination; detail re-fetches the stored snapshot.
    await page.getByRole('navigation', { name: '프로젝트 메뉴' }).waitFor();
    assert.ok(calls.some(c => c.path === '/api/reviews/upload'));
    await page.getByRole('navigation', { name: '앱 메뉴' }).getByRole('link', { name: '새 프로젝트', exact: true }).click();
    await page.getByRole('button', { name: 'GitHub URL 입력', exact: true }).click();
    await page.getByLabel('Repository URL', { exact: true }).fill('https://github.com/example/ui-only-fixture');
    await checkbox.check();
    await page.getByRole('button', { name: '분석 시작', exact: true }).click();
    await page.getByRole('navigation', { name: '프로젝트 메뉴' }).waitFor();
    assert.ok(calls.some(c => c.path === '/api/reviews/github'));
    assert.deepEqual(errors, []);
    assert.ok(calls.some(call => call.path.endsWith('/status') && call.method === 'PATCH'));
    assert.ok(!calls.some(call => /\/ai-(review|summary|priorities|remediation|audit|roadmap)$|compare-latest\/ai$/.test(call.path)), 'no legacy AI generation request');
    assert.equal(calls.filter(call => call.path.endsWith('/report/ai')).length, 1, 'only explicitly confirmed mock PDF call');
    await page.getByRole('button', { name: '로그아웃', exact: true }).click();
    assert.equal(await page.evaluate(() => localStorage.getItem('securedeploy.accessToken')), null);
    console.log(JSON.stringify({ result: 'passed', viewports: ['1440', '390', '320'], views: 6,
      scenarios: ['normal', 'disabled', 'empty', 'legacy'], login: true, history: true, zip: true, github: true,
      statusUpdate: true, pdf: true, aiPdfConfirmation: true, storedGuidance: true, backendSummary: true, legacyAiRequests: 0, realApiCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
