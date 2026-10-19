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
      result.serverAnalysis.deploymentAnalysis = require('../deployment-fixture.cjs')();
      const python = require('../server-analysis-fixture.cjs')();
      python.analyzerVersion = 'py-django-v2'; python.parserVersion = 'CPython-3.14.5';
      python.selectionCoverage={discoveredFiles:3,submittedFiles:2,omittedFiles:1,omittedDetails:0,submittedCharacters:100,omissionReasons:{FILE_COUNT_LIMIT:1}};
      python.files[0].selectionReason='DJANGO_ENTRY_HINT';
      python.files.push({filePath:'app/registry.py',parseStatus:'PARSED',flowStatus:'NOT_SUPPORTED',entrypoints:0,functionsAnalyzed:0,limitations:['NO_SUPPORTED_SERVER_ENTRY_OR_CALL']},
        {filePath:'data/catalog.py',parseStatus:'LIMIT_EXCEEDED',flowStatus:'NOT_RUN',entrypoints:0,functionsAnalyzed:0,limitations:['FILE_COUNT_LIMIT']});
      python.validatedFindings[0].sourceType = 'PYTHON_DATA_FLOW';
      python.validatedFindings[0].ruleId = 'PY_SQL_INPUT_FLOW';
      python.validatedFindings[0].recommendedAction = 'SQL은 고정하고 execute(sql, params) 또는 Django ORM을 사용하세요.';
      python.findings[0].ruleId = 'PY_SQL_INPUT_FLOW';
      result.serverAnalysis.pythonAnalysis = python;
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
      assert.ok((await page.getByRole('region', { name: '서버 코드 흐름 요약', exact: true }).innerText()).includes('별도 결과'));
      await nav.getByRole('button', { name: '배포 전 직접 확인할 부분', exact: true }).click();
      const section = page.getByRole('region', { name: '서버 코드 흐름 검사', exact: true });
      const pythonSection = page.getByRole('region', { name: 'Python 서버 코드 흐름 검사', exact: true });
      const deployment = page.getByRole('region', { name: '서버·배포 설정 검사', exact: true });
      await deployment.waitFor({state:'visible'});
      for (const phrase of ['별도 검토 항목 1건','값 미확인 1건','안전하다는 뜻은 아닙니다','compose.yaml:4','소켓 연결을 제거'])
        assert.ok((await deployment.innerText()).includes(phrase),phrase);
      await deployment.getByText('설정 근거와 한계',{exact:true}).click();
      await deployment.getByText('설정 파일별 검사 범위 (1)',{exact:true}).click();
      await deployment.locator('.coverage-details .technical-details summary').click();
      assert.ok((await deployment.innerText()).includes('값 확인 불가'));
      if(process.env.SCREENSHOT_DIR) {
        await deployment.scrollIntoViewIfNeeded();
        await page.screenshot({path:require('node:path').join(process.env.SCREENSHOT_DIR,`deployment-${width}.png`)});
      }
      await pythonSection.waitFor({ state: 'visible' });
      assert.equal(await pythonSection.locator('article').count(), 1);
      assert.ok((await pythonSection.innerText()).includes('execute(sql, params)'));
      assert.ok((await pythonSection.innerText()).includes('전체 Python 코드'));
      for (const phrase of ['구문 파싱 2개','자원 제한 1개','보안 검사를 모두 마쳤다는 뜻이 아닙니다','미선택 1개'])
        assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      await pythonSection.getByText('파일별 구문 검사·추적 범위 (3)',{exact:true}).click();
      assert.ok((await pythonSection.innerText()).includes('파일 수 상한'));
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
})().catch(error => { console.error('Synthetic server analysis browser assertion failed:', error.message); process.exitCode = 1; });
