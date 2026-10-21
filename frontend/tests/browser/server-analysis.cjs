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
      const javaLocation={filePath:'src/Endpoint.java',line:12,column:5,functionName:'inspect',kind:'SQL_EXECUTION'};
      const javaSource={...javaLocation,line:7,kind:'REQUEST_INPUT'};
      result.serverAnalysis.javaAnalysis={analysis:{version:process.env.JAVA_ANALYZER_VERSION||'java-sql-v1',status:'PARTIAL',
        files:[{filePath:javaLocation.filePath,parseStatus:'PARSED',entrypoints:1,functions:1,sqlCallSites:2,tracedCallSites:1,limitations:['SQL_CALLS_OUTSIDE_TRACED_FLOW']}],
        methods:[],dataAccess:[{framework:'MYBATIS',status:'DECLARED_VALUE_BINDING',operation:'lookup',location:javaLocation,declaration:{...javaLocation,filePath:'mapper/Queries.xml',line:3},trace:[javaSource],limitations:['FRAMEWORK_PROXY_RUNTIME_NOT_VERIFIED']},{framework:'MYBATIS_PLUS',status:'UNKNOWN',operation:'update',location:javaLocation,trace:[],limitations:[]}],uses:[{kind:'INPUT_IN_QUERY',api:'executeQuery',location:javaLocation,trace:[javaSource],bindingCalls:0,limitations:[]}],limitations:['BOUNDED_SPRING_AND_SERVLET_ONLY']},
        suppressedLegacyCount:1,legacyEvidence:[],findings:[{findingId:'java-sql:synthetic-only',ruleId:'JAVA_SQL_INPUT_FLOW',priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',
          location:javaLocation,trace:[javaSource],title:'사용자가 보낸 값이 SQL 명령문에 들어갈 수 있습니다',explanation:'요청 입력이 SQL 실행까지 전달되는 정적 경로이며 실제 공격은 미확인입니다.',
          recommendation:'SQL 문법을 고정하고 PreparedStatement의 set 메서드로 값을 분리하세요.',verificationSteps:['로컬 Mock으로 값 바인딩을 확인하고 재검사하세요.']}]};
      result.serverAnalysis.deploymentAnalysis = require('../deployment-fixture.cjs')();
      const python = require('../server-analysis-fixture.cjs')();
      python.analyzerVersion = 'py-django-v8'; python.parserVersion = 'CPython-3.14.5';
      python.files[0].limitations.push('STRING_FORMAT_UNRESOLVED');
      python.selectionCoverage={discoveredFiles:3,submittedFiles:2,omittedFiles:1,omittedDetails:0,submittedCharacters:100,omissionReasons:{FILE_COUNT_LIMIT:1}};
      python.files[0].selectionReason='DJANGO_ENTRY_HINT';
      python.files.push({filePath:'app/registry.py',parseStatus:'PARSED',flowStatus:'NOT_SUPPORTED',entrypoints:0,functionsAnalyzed:0,limitations:['NO_SUPPORTED_SERVER_ENTRY_OR_CALL']},
        {filePath:'data/catalog.py',parseStatus:'LIMIT_EXCEEDED',flowStatus:'NOT_RUN',entrypoints:0,functionsAnalyzed:0,limitations:['FILE_COUNT_LIMIT']});
      python.validatedFindings[0].sourceType = 'PYTHON_DATA_FLOW';
      python.validatedFindings[0].ruleId = 'PY_SQL_INPUT_FLOW';
      python.validatedFindings[0].recommendedAction = 'SQL은 고정하고 execute(sql, params) 또는 Django ORM을 사용하세요.';
      python.findings[0].ruleId = 'PY_SQL_INPUT_FLOW';
      const resourceFindings=require('../resource-fixture.cjs')();
      python.validatedFindings.push(...resourceFindings);
      python.findings.push(...resourceFindings.flatMap(f=>f.evidence));
      python.resourceUses=resourceFindings.map(f=>({ruleId:f.ruleId,kind:f.ruleId.includes('FILE_PATH')?'INPUT_IN_FILE_PATH':'INPUT_TO_UNSAFE_DESERIALIZATION',location:f.location,trace:f.evidence[0].flow,defenses:[],limitations:f.evidence[0].limitations,executionObserved:true}));
      const authorization=require('../authorization-fixture.cjs')();
      python.authorizationContexts[0].details=authorization.details;
      python.tokenUses=[{operation:'DECODE',location:{filePath:'api/views.py',line:6,functionName:'endpoint'},signatureStatus:'EXPLICITLY_DISABLED',keySource:'UNKNOWN',usageStatus:'ACCESS_REJECTION_BRANCH',trace:[],limitations:['EXTERNAL_TOKEN_VALIDATION_NOT_VERIFIED']}];
      python.exposureUses=[{kind:'HTTP_RESPONSE_RETURN',status:'SENSITIVE_FLOW_CANDIDATE',location:{filePath:'api/views.py',line:9,functionName:'endpoint'},trace:[{filePath:'api/views.py',line:5,kind:'FRAMEWORK_SECRET_SETTING'}],limitations:['STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF']}];
      python.serviceUses=[{kind:'REQUESTS',status:'EXPLICIT_TIMEOUT_DISABLED',location:{filePath:'api/views.py',line:11,functionName:'endpoint'},trace:[],limitations:['STATIC_CALL_NOT_SERVICE_FAILURE_PROOF']}];
      result.serverAnalysis.exposureUses=[{...python.exposureUses[0],kind:'LOG_ARGUMENT',status:'SENSITIVITY_UNVERIFIED',trace:[{filePath:'worker.ts',line:3,kind:'ENVIRONMENT_VALUE_UNVERIFIED'}]}];
      python.validatedFindings.push(authorization.finding);python.findings.push(authorization.evidence);
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
      const nodeSource={filePath:'routes/task.cjs',line:3,column:1,functionName:'handle',kind:'EXPRESS_BODY'};
      const nodeSink={...nodeSource,line:5,kind:'EVAL_CALL'};
      const nodeEvidence={ruleId:'JS_EVAL_INPUT_FLOW',kind:'CWE-95',confidence:'HIGH',disposition:'REVIEW_REQUIRED',source:nodeSource,sink:nodeSink,flow:[nodeSource],defenses:[],limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF'],message:'요청 입력이 코드 실행 호출로 전달됩니다.',recommendation:'eval 대신 입력 타입 검증과 숫자 변환을 사용하세요.'};
      result.serverAnalysis.findings.push(nodeEvidence);
      result.serverAnalysis.validatedFindings.push({findingId:'ts-flow:synthetic-express',sourceType:'TYPESCRIPT_DATA_FLOW',analyzerVersion:'ts-server-v7',ruleId:nodeEvidence.ruleId,priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',location:nodeSink,evidence:[nodeEvidence],executionLocations:[nodeSink],title:'사용자가 보낸 값이 서버에서 코드로 실행될 수 있습니다',riskExplanation:'정적 전달 근거이며 실제 공격은 미검증입니다.',recommendedAction:nodeEvidence.recommendation,verificationSteps:['로컬 Mock으로 검증 후 재검사하세요.']});
      result.serverAnalysis.nodeUses=[{ruleId:nodeEvidence.ruleId,kind:'INPUT_TO_EXECUTION',operation:'EVAL_CALL',location:nodeSink,trace:[nodeSource],limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF']},{ruleId:'JS_MONGO_WHERE_INPUT_FLOW',kind:'RECEIVER_NOT_VERIFIED',operation:'find',location:nodeSink,trace:[],limitations:['MONGODB_RECEIVER_OR_OBJECT_FLOW_UNRESOLVED']}];
      for(const kind of ['CONSTRUCTOR_SUMMARY_MUST','CONSTRUCTOR_SUMMARY_UNKNOWN','CURSOR_CREATED_EXECUTION_NOT_OBSERVED'])result.serverAnalysis.nodeUses.push({ruleId:kind.startsWith('CONSTRUCTOR')?'JS_CONSTRUCTOR_EFFECT':'JS_MONGO_WHERE_INPUT_FLOW',kind,operation:'STATIC_ONLY',location:nodeSink,trace:[],limitations:['NOT_WHOLE_FUNCTION_FLOW']});
      result.serverAnalysis.analyzerVersion='ts-server-v11';
      for(const kind of ['ENTRY_REGISTERED','CALL_LINKED','CALLBACK_BOUND','AUTHENTICATOR_REFERENCED'])result.serverAnalysis.nodeUses.push({ruleId:'JS_SERVER_ENTRY_CONTEXT',kind,operation:'STATIC_ONLY',location:nodeSink,trace:[],limitations:['INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED']});
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
      const java = page.getByRole('region', { name: 'Java SQL 코드 흐름 검사', exact: true });
      await java.waitFor({state:'visible'});
      await java.locator('article').first().waitFor({state:'visible'});
      for(const phrase of ['별도 확인 후보 1건','실제 공격은 미확인','PreparedStatement','NOT_COMPARED']) {
        if(phrase==='NOT_COMPARED')await java.getByText('입력 전달 경로와 기술 정보',{exact:true}).click();
        assert.ok((await java.innerText()).includes(phrase),phrase);
      }
      await java.getByText('Java 검사 범위와 SQL 호출 근거',{exact:true}).click();
      for(const phrase of ['SQL 호출 구문 2 / 추적 1','기존 정상 패턴 신호 제외 1건','전체 Java 코드가 안전하다는 뜻이 아닙니다'])
        assert.ok((await java.innerText()).includes(phrase),phrase);
      await java.getByText('클래스 간 전달과 저장소 선언 근거 (2)',{exact:true}).click();
      for(const phrase of ['정적 SQL 선언과 값 바인딩 확인','호출·SQL 구성 미확인','mapper/Queries.xml:3','안전이나 취약점 확정이 아닙니다'])assert.ok((await java.innerText()).includes(phrase),phrase);
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
      assert.equal(await pythonSection.locator('article').count(), 4);
      for(const phrase of ['사용자가 입력한 경로로 서버가 다른 파일','외부에서 받은 데이터를 위험한 방식','YAML SafeLoader'])assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      await pythonSection.getByText('파일 접근·데이터 복원 근거 (2)',{exact:true}).click();
      await pythonSection.getByText('토큰 서명·사용 근거 (1)',{exact:true}).click();
      await pythonSection.getByText('응답·로그 정보 전달 근거 (1)',{exact:true}).click();
      await pythonSection.getByText('외부 요청 대기 제한 근거 (1)',{exact:true}).click();
      for(const phrase of ['타임아웃을 명시적으로 해제','운영 장애는 미확인','지연 Mock'])assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      for(const phrase of ['실제 유출은 미검증','서버 비밀 설정 참조','기존 위험 건수·점수에는 합산하지 않습니다'])assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      await section.getByText('응답·로그 정보 전달 근거 (1)',{exact:true}).click();
      assert.ok((await section.innerText()).includes('정보가 실제로 민감한지 확인하지 못함'));
      for(const phrase of ['서명 검증 생략 옵션 확인','접근 거부 조건','실제 설치 라이브러리','api/views.py:6'])assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      assert.ok((await pythonSection.innerText()).includes('심볼릭 링크'));
      await pythonSection.getByText('인증·권한 관련 문맥 (1)',{exact:true}).click();
      const authPanel=pythonSection.locator('.authorization-context-details');
      for(const phrase of ['로그인 요구 선언 확인','객체 소유권 검사는 아님','소유자 일치 시 차단','app/views.py:8'])assert.ok((await authPanel.innerText()).includes(phrase),phrase);
      if(process.env.SCREENSHOT_DIR)await authPanel.screenshot({path:require('node:path').join(process.env.SCREENSHOT_DIR,`authorization-${width}.png`)});
      if(process.env.SCREENSHOT_DIR) await pythonSection.locator('article').nth(1).screenshot({path:require('node:path').join(process.env.SCREENSHOT_DIR,`file-flow-${width}.png`)});
      assert.ok((await pythonSection.innerText()).includes('execute(sql, params)'));
      assert.ok((await pythonSection.innerText()).includes('전체 Python 코드'));
      assert.ok((await pythonSection.innerText()).includes('문자열 포맷이 동적이거나 지원 범위를 벗어나'));
      for (const phrase of ['구문 파싱 2개','자원 제한 1개','보안 검사를 모두 마쳤다는 뜻이 아닙니다','미선택 1개'])
        assert.ok((await pythonSection.innerText()).includes(phrase),phrase);
      await pythonSection.getByText('파일별 구문 검사·추적 범위 (3)',{exact:true}).click();
      assert.ok((await pythonSection.innerText()).includes('파일 수 상한'));
      assert.ok((await section.innerText()).includes('functions/api/items.ts:3'));
      assert.equal(await section.locator('article').count(), 3);
      await section.getByText('Express 코드 실행·데이터 접근 근거 (9)',{exact:true}).click();
      for(const phrase of ['서버에서 코드로 실행될 수 있습니다','요청 본문','객체 출처 또는 값 전달을 확인하지 못함','소유권 검증의 증명이 아니며'])assert.ok((await section.innerText()).includes(phrase),phrase);
      for(const phrase of ['제한된 생성자의 필드 전달·읽기 효과 확인','생성자 효과를 확인하지 못함','커서 구성 단계 · 이 근거만으로 실행은 미확인'])assert.ok((await section.innerText()).includes(phrase),phrase);
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
