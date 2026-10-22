// Actual JWT/H2/workspace API and browser. The model and GitHub source are explicit test-only mocks.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {execFileSync}=require('node:child_process');
const origin=process.env.FRONTEND_URL||'http://localhost:5173',api='http://127.0.0.1:8085';
(async()=>{
 const http=await request.newContext({baseURL:api}),browser=await chromium.launch({headless:true});let temp;
 try{
  const login=await http.post('/api/auth/login',{data:{email:'editing-browser@example.invalid',password:'Synthetic-Local-813!'}});assert.equal(login.status(),200);
  const user=await login.json(),headers={Authorization:`Bearer ${user.accessToken}`};
  const reviews=await (await http.get('/api/reviews',{headers})).json(),review=reviews.find(r=>r.sourceType==='GITHUB');assert.ok(review);
  const savedBefore=await (await http.get(`/api/reviews/${review.reviewId}`,{headers})).json();
  temp=fs.mkdtempSync(path.join(os.tmpdir(),'securedeploy-ai-patch-'));
  for(const width of [1440,390,320]){
   const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true}),errors=[],outbound=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
   await page.addInitScript(auth=>{localStorage.setItem('securedeploy.accessToken',auth.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));},user);
   await page.route('**/*',route=>{const url=new URL(route.request().url());if(url.pathname.startsWith('/api/'))return route.continue({url:api+url.pathname+url.search});if(url.origin===new URL(origin).origin)return route.continue();outbound.push(url.origin);return route.abort();});
   await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);
   await page.getByRole('button',{name:'수정 작업 공간 열기',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();
   await page.getByRole('button',{name:'application.properties',exact:true}).click();const panel=page.getByLabel('AI 보안 수정안',{exact:true});
   await panel.getByLabel('수정할 분석 항목').selectOption({label:'DEBUG_ENABLED · 원본 1행'});
   await panel.getByRole('button',{name:'AI 수정안 전송 범위 확인'}).click();await panel.getByText('코드 전송 동의 대기',{exact:true}).waitFor();
   assert.ok(await panel.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).isDisabled());
   assert.equal(await page.locator('#source-code').inputValue(),'debug=true\nserver.error.include-stacktrace=always\n');
   await panel.getByLabel('이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.').check();
   await panel.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).click();await panel.getByText('제안 · 미적용',{exact:true}).waitFor();
   assert.equal(await page.locator('#source-code').inputValue(),'debug=true\nserver.error.include-stacktrace=always\n');
   assert.ok(await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).isDisabled());
   await panel.getByLabel('Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.').check();
   await panel.getByRole('button',{name:'검토한 AI 수정안 적용'}).click();await panel.getByText('작업 공간 적용됨 · 해결 미검증',{exact:true}).waitFor();
   await page.waitForFunction(()=>document.querySelector('#source-code')?.value.startsWith('debug=false'));
   await page.locator('#source-code').fill('debug=false\nserver.error.include-stacktrace=always\n# manual\n');await page.getByRole('button',{name:'변경 저장',exact:true}).click();
   await panel.getByLabel('수정할 분석 항목').selectOption({label:'STACKTRACE_EXPOSURE · 원본 2행'});
   await panel.getByRole('button',{name:'AI 수정안 전송 범위 확인'}).click();await panel.getByText('코드 전송 동의 대기',{exact:true}).waitFor();
   await panel.getByLabel('이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.').check();await panel.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).click();
   await panel.getByText('제안 · 미적용',{exact:true}).waitFor();await panel.getByRole('button',{name:'제안 거절',exact:true}).click();await panel.getByText('거절됨 · 변경 없음',{exact:true}).waitFor();
   assert.ok((await page.locator('#source-code').inputValue()).includes('include-stacktrace=always'));
   await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();await page.locator('.source-export-approval').last().locator('input').check();
   const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).click();
   const download=await downloadPromise,zip=path.join(temp,'edited.zip');await download.saveAs(zip);
   const result=execFileSync('python3',['-c',`import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
 assert z.read('application.properties')==b'debug=false\\nserver.error.include-stacktrace=always\\n# manual\\n'
print('MATCH')`,zip],{encoding:'utf8'});assert.equal(result.trim(),'MATCH');
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
   await page.screenshot({path:`/private/tmp/securedeploy-ai-patch-${width}.png`,fullPage:true});
   page.on('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();await page.close();
  }
  assert.deepEqual(await (await http.get(`/api/reviews/${review.reviewId}`,{headers})).json(),savedBefore);
  console.log(JSON.stringify({passed:true,widths:[1440,390,320],api:'ACTUAL_H2_JWT_WORKSPACE',model:'MOCK_ONLY',source:'MOCK_GITHUB',approvalAndRejection:true,zipMatchesAcceptedOnly:true,reviewUnchanged:true,paidCalls:0}));
 }finally{await browser.close();await http.dispose();if(temp)fs.rmSync(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
