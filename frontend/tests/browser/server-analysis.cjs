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
      const ssrfSource={filePath:'functions/proxy.ts',line:3,functionName:'onRequest',kind:'REQUEST_HEADER'};
      const ssrfSink={...ssrfSource,line:5,kind:'HTTP_REQUEST_CALL'};
      const ssrf={ruleId:'TS_SSRF_INPUT_FLOW',kind:'INPUT_TO_HTTP_DESTINATION',confidence:'HIGH',disposition:'REVIEW_REQUIRED',
        source:ssrfSource,sink:ssrfSink,flow:[ssrfSource],defenses:[],limitations:['REDIRECT_DNS_REACHABILITY_NOT_VERIFIED'],
        message:'사용자 입력이 서버의 요청 주소에 전달됩니다.',recommendation:'파싱한 프로토콜과 호스트를 정확한 허용 목록으로 제한하세요.'};
      result.serverAnalysis.findings.push(ssrf);
      result.serverAnalysis.validatedFindings.push({findingId:'ts-flow:synthetic-ssrf-only',sourceType:'TYPESCRIPT_DATA_FLOW',analyzerVersion:'ts-server-v4',
        ruleId:ssrf.ruleId,priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',location:ssrfSink,evidence:[ssrf],executionLocations:[ssrfSink],
        title:'사용자가 입력한 주소로 서버가 요청을 보낼 수 있습니다',riskExplanation:'의도하지 않은 서비스로 요청할 가능성이 있으나 실제 내부망 접근은 검증하지 않았습니다.',
        recommendedAction:ssrf.recommendation,verificationSteps:['허용되지 않은 목적지가 차단되는지 로컬 Mock으로 확인하세요.','수정 후 재검사하세요.']});
      result.serverAnalysis.httpUses=[{kind:'INPUT_IN_DESTINATION',controlledPart:'WHOLE_URL',location:ssrfSink,trace:[ssrfSource],defenses:[],limitations:ssrf.limitations}];
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
      assert.equal(await section.locator('article').count(), 2);
      for (const title of ['Finding 기술 근거와 한계', '쿼리 값 처리와 방어 근거 (1)', '서버 HTTP 요청 목적지 (1)', '인증·권한 관련 문맥 (1)', '파일별 구문 검사·추적 범위 (1)'])
        for(const element of await section.getByText(title, { exact: true }).all()) await element.click();
      assert.ok((await section.innerText()).includes('접근 권한 취약점으로 판단하지 않습니다'));
      assert.ok((await section.innerText()).includes('functions/api/items.ts:7'));
      assert.ok((await section.innerText()).includes('NOT_COMPARED'));
      assert.ok((await section.innerText()).includes('사용자가 입력한 주소로 서버가 요청'));
      assert.ok((await section.innerText()).includes('안전하다고 보증하지 않습니다'));
      if(process.env.SCREENSHOT_DIR) await page.screenshot({path:require('node:path').join(process.env.SCREENSHOT_DIR,`ssrf-${width}.png`),fullPage:true});
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow ${width}`);
      assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
      console.log(JSON.stringify({ width, structuralEvidence: 'PASS', boundedCoverage: 'PASS', externalRequests: 0 }));
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(() => { console.error('Server analysis browser assertion failed'); process.exitCode = 1; });
