// Real React/upload/JWT/H2, synthetic ZIP only. No GitHub or paid AI calls.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const {stage,pane,resultView}=require('./editor-navigation.cjs');
const api=process.env.API_BASE_URL||'http://127.0.0.1:8085',origin=process.env.FRONTEND_URL||'http://localhost:5173';
const files={'application.properties':'debug=true\nserver.error.include-stacktrace=always\n','notes/very-long-file-name-used-to-check-file-navigation-and-wrapping.txt':'static fixture\n'};
const zip=execFileSync('python3',['-c',"import io,sys,json,zipfile\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z:\n for p,s in json.load(sys.stdin).items():z.writestr(p,s)\nsys.stdout.buffer.write(b.getvalue())"],{input:JSON.stringify(files)});
(async()=>{const browser=await chromium.launch(),http=await request.newContext({baseURL:api}),report=[];
try{for(const width of [1440,1024,768,390,320]){
 const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true}),errors=[],outbound=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 // Test-only proxy adapts a separate Vite port to the configured development origin.
 // This exercises real API responses, not production CORS eligibility.
 await page.route('**/*',async r=>{const u=new URL(r.request().url());if(u.pathname.startsWith('/api/')){
  const response=await r.fetch({url:api+u.pathname+u.search,headers:{...r.request().headers(),origin:'http://localhost:5173'}});return r.fulfill({response});
 }if(u.origin===origin)return r.continue();outbound.push(u.origin);return r.abort();});
 const signup=await http.post('/api/auth/signup',{data:{email:`phase2-${width}-${Date.now()}@example.invalid`,name:'UI fixture',password:'Synthetic-Local-813!'}});assert.equal(signup.status(),200);const user=await signup.json();
 await page.addInitScript(auth=>{localStorage.setItem('securedeploy.accessToken',auth.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));},user);
 const check=async name=>{assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),name);assert.deepEqual(errors,[]);await page.screenshot({path:`/private/tmp/sd-ui-phase2-${name}-${width}.png`,fullPage:true});};
 await page.goto(origin+'/#/new');await page.getByLabel('ZIP 파일 선택').setInputFiles({name:'phase2-static.zip',mimeType:'application/zip',buffer:zip});await check('new');
 const uploaded=page.waitForResponse(r=>r.url().endsWith('/api/reviews/upload')&&r.request().method()==='POST');await page.getByRole('button',{name:'분석 시작',exact:true}).click();const response=await uploaded;assert.equal(response.status(),200);const result=await response.json();
 await page.getByRole('navigation',{name:'분석 결과 메뉴'}).waitFor();await check('summary');
 await resultView(page,'수정 권장');await check('findings');
 await page.getByRole('button',{name:'이 파일 수정하기',exact:true}).first().click();await page.getByLabel('원본 ZIP',{exact:true}).setInputFiles({name:'phase2-static.zip',mimeType:'application/zip',buffer:zip});await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();
 await page.getByLabel('프로젝트 파일',{exact:true}).waitFor({state:'attached'});await pane(page,'파일');
 await page.getByRole('searchbox',{name:'파일 찾기'}).fill('not-present');await page.getByText('일치하는 파일이 없습니다.',{exact:true}).waitFor();
 await page.getByRole('searchbox',{name:'파일 찾기'}).fill('application');await page.getByRole('button',{name:'application.properties',exact:true}).click();await page.locator('#source-code').waitFor();
 await page.locator('#source-code').focus();assert.ok(await page.locator('#source-code').evaluate(e=>e===document.activeElement&&getComputedStyle(e).outlineStyle!=='none'));
 const long='debug=false\n# '+ 'static-line-'.repeat(120)+'\nserver.error.include-stacktrace=never\n';await page.locator('#source-code').fill(long);await check('editor');
 assert.ok(await page.locator('#source-code').evaluate(e=>e.scrollWidth>e.clientWidth));await page.getByRole('button',{name:'변경 저장',exact:true}).click();
 await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();await page.getByLabel('변경 전후 코드 Diff',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).isDisabled(),true);await check('diff');
 await page.locator('.source-export-approval input').check();const downloading=page.waitForEvent('download');await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).click();assert.ok((await downloading).suggestedFilename().endsWith('.zip'));
 await stage(page,'재검사 · 비교');const scan=page.getByLabel('수정본 보안 재검사',{exact:true});await scan.getByRole('checkbox').check();await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).waitFor({timeout:30000});
 assert.ok((await scan.innerText()).includes('과거 Review의 경고를 해결 처리하지 않습니다'));
 const contrast=await page.locator('.progress-filters button[aria-pressed=true]').evaluate(e=>{
  const css=getComputedStyle(e),lum=s=>{const c=s.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;});return c[0]*.2126+c[1]*.7152+c[2]*.0722;};
  const a=lum(css.color),b=lum(css.backgroundColor);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
 });assert.ok(contrast>=4.5,'selected comparison text contrast');
 await check('comparison');assert.deepEqual(outbound,[]);
 page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();await page.close();report.push({width,uploadReview:result.reviewId,unverifiedZipComparisonBlocked:true,overflow:false,download:true});
}console.log(JSON.stringify({passed:true,actualH2:true,providerCalls:0,report}));}
finally{await browser.close();await http.dispose();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
