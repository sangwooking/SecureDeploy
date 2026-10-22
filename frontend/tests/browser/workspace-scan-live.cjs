// Actual JWT, isolated H2, production scan/comparison pipeline; source and model are test-only mocks.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const {stage,pane}=require('./editor-navigation.cjs');
const origin=process.env.FRONTEND_URL||'http://localhost:5173',api='http://127.0.0.1:8085';
(async()=>{
 const http=await request.newContext({baseURL:api}),browser=await chromium.launch({headless:true});
 try{
  for(const width of [1440,390,320]){
   const response=await http.post('/api/auth/login',{data:{email:`scan-${width}@example.invalid`,password:'Synthetic-Local-813!'}});assert.equal(response.status(),200);
   const auth=await response.json(),headers={Authorization:`Bearer ${auth.accessToken}`};
   const history=await(await http.get('/api/reviews',{headers})).json(),review=history.find(r=>r.sourceType==='GITHUB');assert.ok(review);
   const original=await(await http.get(`/api/reviews/${review.reviewId}`,{headers})).json();
   const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],outbound=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(user=>{localStorage.setItem('securedeploy.accessToken',user.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(user.user));},auth);
   await page.route('**/*',route=>{const url=new URL(route.request().url());if(url.pathname.startsWith('/api/'))return route.continue({url:api+url.pathname+url.search});if(url.origin===new URL(origin).origin)return route.continue();outbound.push(url.origin);return route.abort();});
   await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);
   await page.getByRole('button',{name:'수정 작업 공간 열기',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();
   await page.getByRole('button',{name:'application.properties',exact:true}).click();
   await pane(page,'수정 근거 · AI');const ai=page.getByLabel('AI 보안 수정안',{exact:true}),scan=page.getByLabel('수정본 보안 재검사',{exact:true});
   await ai.getByLabel('수정할 분석 항목').selectOption({label:'DEBUG_ENABLED · 원본 1행'});
   await ai.getByRole('button',{name:'AI 수정안 전송 범위 확인'}).click();await ai.getByLabel('이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.').check();
   await ai.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).click();await ai.getByText('제안 · 미적용',{exact:true}).waitFor();
   await ai.getByLabel('Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.').check();await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).click();
   await page.waitForFunction(()=>document.querySelector('#source-code')?.value.startsWith('debug=false'));
   await stage(page,'재검사 · 비교');assert.ok(await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).isDisabled());
   await scan.getByRole('checkbox').check();await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();
   await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).waitFor({timeout:30000});
   assert.ok((await scan.innerText()).includes('경고가 재탐지되지 않았다는 뜻'));
   await scan.getByRole('button',{name:/해결된 문제/}).click();await scan.getByText('비교 가능한 현재 분석에서 기존 문제가 더 이상 확인되지 않았습니다. 완전한 안전을 보장하지 않습니다.',{exact:true}).waitFor();
   await stage(page,'코드 편집');await pane(page,'코드');await page.locator('#source-code').fill('debug=false\nserver.error.include-stacktrace=always\nserver.servlet.session.cookie.secure=false\n');await page.getByRole('button',{name:'변경 저장',exact:true}).click();await stage(page,'재검사 · 비교');
   await scan.getByText(/최신 수정본은 아직 재검사되지 않았습니다/).waitFor();
   await scan.getByRole('checkbox').check();await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();
   await scan.getByText(/검사 revision 3 · 고정된 revision/).waitFor({timeout:30000});
   await scan.getByRole('button',{name:/새로 발견된 문제/}).click();assert.ok((await scan.innerText()).includes('쿠키'));
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
   await page.screenshot({path:`/private/tmp/securedeploy-workspace-scan-${width}.png`,fullPage:true});
   const url=await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).getAttribute('href'),newId=new URLSearchParams(url.split('?')[1]).get('review');
   const saved=await(await http.get(`/api/reviews/${newId}`,{headers})).json();assert.equal(saved.sourceType,'WORKSPACE');assert.equal(saved.workspaceScan.revision,3);assert.equal(saved.workspaceScan.sourceRevision,'a'.repeat(40));
   assert.ok(saved.comparison.counts.RESOLVED>0);assert.ok(saved.comparison.counts.NEW>0);assert.ok(saved.comparison.counts.REMAINING>0);
   page.on('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();
   assert.deepEqual(await(await http.get(`/api/reviews/${newId}`,{headers})).json(),saved);assert.deepEqual(await(await http.get(`/api/reviews/${review.reviewId}`,{headers})).json(),original);
   await page.goto(origin+'/'+url);await page.getByText(/작업 공간 수정본 검사 · revision 3/).waitFor();
   await page.goto(`${origin}/#/projects/${review.projectId}/history`);await page.getByRole('heading',{name:/^분석 이력 \(/}).waitFor();
   await page.getByText(`분석 #${newId}`,{exact:false}).waitFor();await page.getByText(/작업 공간 수정본 ·/).first().waitFor();
   await page.close();
  }
  console.log(JSON.stringify({passed:true,widths:[1440,390,320],engine:'ACTUAL_STANDARD',storage:'ISOLATED_H2',source:'MOCK_GITHUB',ai:'MOCK_ONLY',paidCalls:0,afterDeletion:true,originalUnchanged:true}));
 }finally{await browser.close();await http.dispose();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
