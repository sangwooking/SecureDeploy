// Run against Vite with Playwright installed, or set PLAYWRIGHT_MODULE to its module path.
// No request reaches a backend or external API. All credentials and responses are synthetic.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fixture = require('../result-fixture.cjs');
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
      if (path === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
      if (path === '/api/auth/login') return json({ accessToken: 'ui-fixture-not-a-real-token', tokenType: 'Bearer',
        user: { id: 1, email: 'ui@example.invalid', name: '테스트 사용자' } });
      if (path === '/api/reviews' && request.method() === 'GET') return json([{ ...result, sourceType: 'ZIP', createdAt: '2026-10-12T00:00:00Z' }]);
      if (path === '/api/reviews/101') return json(responseFixture());
      if (path === '/api/reviews/upload' || path === '/api/reviews/github') {
        const enhanced = request.postData()?.includes('AI_ENHANCED');
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
      if (path === '/api/reviews/101/ai-summary') return json({ reviewId: 101, generatedAt: '2026-10-12T00:00:00Z',
        overallSecurityStatus: '테스트 종합 의견', mostRiskyArea: '인증정보 관리', priorityFixes: ['키 교체'],
        preDeploymentActions: ['재검사'], deploymentOpinion: '저장된 배포 판단을 우선 확인하세요.' });
      if (path === '/api/reviews/101/report') return route.fulfill({ status: 200, contentType: 'application/pdf', body: '%PDF-1.4\n% mock download fixture' });
      if (path === '/api/reviews/101/ai-roadmap') return route.fulfill({ status: 503, contentType: 'application/json',
        body: JSON.stringify({ message: '테스트용 안내: 잠시 후 다시 시도해 주세요.' }) });
      return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ message: 'Mock route missing' }) });
    });
    await page.goto(url);
    await page.getByLabel('이메일', { exact: true }).fill('ui@example.invalid');
    await page.getByLabel('비밀번호', { exact: true }).fill('fake-ui-test-password');
    await page.locator('.auth-submit').click();
    await page.locator('.history-item').click();
    const navigate = async name => {
      await page.getByRole('navigation', { name: '분석 결과 메뉴' }).getByRole('button', { name, exact: true }).click();
      await page.waitForTimeout(60);
    };
    const visible = () => page.locator('#result-content').innerText();
    const openDetails = async selector => {
      const element = page.locator(selector);
      if (!(await element.evaluate(el => el.open))) await element.locator(':scope > summary').click();
    };
    assert.ok((await visible()).includes('배포 전 수정 필요'));
    for (const word of ['CVE-', 'HARDCODED_SECRET', 'fixture-model', 'Confidence']) assert.ok(!(await visible()).includes(word));
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844], ['small-mobile', 320, 740]]) {
      await page.setViewportSize({ width, height });
      await navigate('결과 요약');
      for (const section of ['결과 요약', '반드시 처리', '확인 필요', '수정 권장', '해결 방법', '기술 정보']) {
        await navigate(section);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), name + ': ' + section + ' overflow');
        if (section === '반드시 처리') {
          const card = page.locator('.action-finding').first();
          assert.ok(!(await visible()).includes('Confidence'));
          await card.locator(':scope > .technical-details > summary').click();
          assert.ok((await visible()).includes('secret = <redacted>'));
          await card.locator(':scope > .technical-details > summary').click();
          await page.getByLabel('심각도', { exact: false }).selectOption('LOW');
          assert.ok((await visible()).includes('선택한 심각도'));
          await page.getByLabel('심각도', { exact: false }).selectOption('ALL');
        }
        if (section === '확인 필요') {
          assert.equal(await page.locator('.semantic-candidate').count(), 1);
          assert.ok(!(await visible()).includes('IDOR'));
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
        if (['결과 요약', '반드시 처리', '확인 필요'].includes(section)) {
          await page.screenshot({ path: `/private/tmp/securedeploy-result-${name}-${['결과 요약', '반드시 처리', '확인 필요'].indexOf(section)}.png`, fullPage: true });
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
    await navigate('해결 방법');
    await page.getByText('AI와 더 자세히 검토하기', { exact: true }).click();
    await page.getByRole('button', { name: 'AI 종합 진단', exact: true }).click();
    await page.getByRole('button', { name: 'AI 종합 진단 생성', exact: true }).click();
    await page.getByText('테스트 종합 의견', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'AI 개선 로드맵', exact: true }).click();
    await page.getByRole('button', { name: 'AI 보안 개선 로드맵 생성', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: '테스트용 안내' }).waitFor();
    for (const current of ['disabled', 'empty', 'legacy']) {
      scenario = current;
      await openDetails('.history-panel');
      await page.locator('.history-item').click();
      await navigate('결과 요약');
      if (current === 'disabled') assert.ok((await visible()).includes('외부 AI 분석이 비활성화'));
      if (current === 'legacy') assert.ok((await visible()).includes('미평가'));
      await navigate('확인 필요');
      if (current === 'empty') assert.ok((await visible()).includes('후보 0건은 안전을 의미하지 않습니다'));
      if (current === 'legacy') assert.ok((await visible()).includes('우선순위가 저장되지 않은 코드 문제'));
    }
    scenario = 'normal';
    await openDetails('.analysis-entry');
    const checkbox = page.getByRole('checkbox');
    assert.equal(await checkbox.isChecked(), false);
    await page.locator('input[type=file]').setInputFiles({ name: 'ui-fixture.zip', mimeType: 'application/zip', buffer: Buffer.from('not sent to backend') });
    await page.getByRole('button', { name: '분석 시작', exact: true }).click();
    await page.getByText('기본 분석으로 진행하여 AI 추가 코드 검토는 실행하지 않았습니다.', { exact: true }).waitFor();
    await openDetails('.analysis-entry');
    await page.getByRole('button', { name: 'GitHub URL 입력', exact: true }).click();
    await page.getByLabel('Repository URL', { exact: true }).fill('https://github.com/example/ui-only-fixture');
    await checkbox.check();
    await page.getByRole('button', { name: '분석 시작', exact: true }).click();
    await page.getByText('선택된 코드 영역의 AI 추가 검토를 완료했습니다.', { exact: true }).waitFor();
    assert.deepEqual(errors, []);
    assert.ok(calls.some(call => call.path.endsWith('/status') && call.method === 'PATCH'));
    await page.getByRole('button', { name: '로그아웃', exact: true }).click();
    assert.equal(await page.evaluate(() => localStorage.getItem('securedeploy.accessToken')), null);
    console.log(JSON.stringify({ result: 'passed', viewports: ['1440', '390', '320'], views: 6,
      scenarios: ['normal', 'disabled', 'empty', 'legacy'], login: true, history: true, zip: true, github: true,
      statusUpdate: true, pdf: true, aiSummary: true, errorFeedback: true, realApiCalls: 0 }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
