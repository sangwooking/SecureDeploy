const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {stage,pane}=require('./editor-navigation.cjs');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const origin=process.env.FRONTEND_URL||'http://localhost:5173',api='http://127.0.0.1:8085';
const original="export const value = 'original';\n";
const modified="export const value = 'edited';\n";
const malicious='<script>window.__sourceExecuted=true</script>';
const zip=execFileSync('python3',['-c',`import io,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('src/example.ts',${JSON.stringify(original)})
 z.writestr('assets/example.bin',bytes([0,255,2]))
 z.writestr('static/example.html',${JSON.stringify(malicious)})
sys.stdout.buffer.write(b.getvalue())`]);
(async()=>{
 const http=await request.newContext({baseURL:api}),browser=await chromium.launch({headless:true});
 let temp;
 try{
  let response=await http.post('/api/auth/login',{data:{email:'editing-browser@example.invalid',password:'Synthetic-Local-813!'}});
  assert.equal(response.status(),200);const user=await response.json(),headers={Authorization:`Bearer ${user.accessToken}`};
  response=await http.get('/api/reviews',{headers});const github=(await response.json()).find(r=>r.sourceType==='GITHUB');assert.ok(github);
  response=await http.post('/api/reviews/upload',{headers,multipart:{scanMode:'STANDARD',file:{name:'source-fixture.zip',mimeType:'application/zip',buffer:zip}}});
  assert.equal(response.status(),200);const zipReview=await response.json();
  temp=fs.mkdtempSync(path.join(os.tmpdir(),'securedeploy-edit-export-'));
  for(const kind of ['ZIP','GITHUB'])for(const width of [1440,390,320]){
   const review=kind==='ZIP'?zipReview:github;
   const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true}),errors=[],unexpected=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
   await page.addInitScript(auth=>{localStorage.setItem('securedeploy.accessToken',auth.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));},user);
   await page.route('**/*',route=>{
    const url=new URL(route.request().url());if(url.pathname.startsWith('/api/'))return route.continue({url:api+url.pathname+url.search});
    if(url.origin===new URL(origin).origin)return route.continue();unexpected.push(url.origin);return route.abort();
   });
   await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);
   await page.getByRole('button',{name:'수정 작업 공간 열기',exact:true}).click();
   if(kind==='ZIP')await page.locator('input[type=file]').setInputFiles({name:'source-fixture.zip',mimeType:'application/zip',buffer:zip});
   await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();
   await page.getByRole('button',{name:'example.ts',exact:true}).click();
   const editor=page.getByLabel('파일 내용',{exact:true});await editor.waitFor();assert.equal(await editor.inputValue(),original);
   if(kind==='ZIP')assert.ok(await page.getByText('원본 일치 미검증 · 기존 Finding 위치 연결 안 함 · 수정 후 새 분석 필요').isVisible());
   await stage(page,'변경 검토 · 다운로드');assert.ok(await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).isDisabled());await stage(page,'코드 편집');
   await editor.fill(modified);await page.getByRole('button',{name:'변경 저장',exact:true}).click();
   await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인',exact:true}).click();
   await page.locator('.source-diff pre').waitFor();const diff=await page.locator('.source-diff pre').innerText();
   assert.ok(diff.includes("-export const value = 'original';"));assert.ok(diff.includes("+export const value = 'edited';"));
   await page.locator('.source-export-approval input').check();
   let downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'수정본 ZIP 다운로드',exact:true}).click();
   let download=await downloadPromise;const zipPath=path.join(temp,'edited.zip');await download.saveAs(zipPath);
   const check=execFileSync('python3',['-c',`import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
 assert z.read('src/example.ts')==${JSON.stringify(modified)}.encode()
 assert z.read('assets/example.bin')==bytes([0,255,2])
print('MATCH')`,zipPath],{encoding:'utf8'});assert.equal(check.trim(),'MATCH');
   await page.locator('.source-export-approval input').check();downloadPromise=page.waitForEvent('download');
   await page.getByRole('button',{name:'Patch 다운로드',exact:true}).click();download=await downloadPromise;const patchPath=path.join(temp,'edited.patch');await download.saveAs(patchPath);
   const patch=fs.readFileSync(patchPath,'utf8');assert.equal(patch.trim(),diff.trim());
   fs.mkdirSync(path.join(temp,'src'),{recursive:true});fs.writeFileSync(path.join(temp,'src/example.ts'),original);
   execFileSync('git',['apply','--check',patchPath],{cwd:temp,stdio:'pipe'});
   if(kind==='ZIP'){
    await stage(page,'코드 편집');await pane(page,'파일');await page.getByRole('button',{name:'example.html',exact:true}).click();await page.locator('#source-code').waitFor();assert.equal(await page.locator('#source-code').inputValue(),malicious);
    assert.equal(await page.evaluate(()=>window.__sourceExecuted),undefined);
   }
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);
   await page.screenshot({path:`/private/tmp/securedeploy-editing-${kind}-${width}.png`,fullPage:true});
   page.on('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();
   await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();await page.close();
  }
  console.log(JSON.stringify({passed:true,zip:'ACTUAL_H2_API',github:'MOCK_SOURCE_ACTUAL_EDITING_API',widths:[1440,390,320],zipBytesVerified:true,patchApplyCheck:true,sourceExecution:false}));
 }finally{await browser.close();await http.dispose();if(temp)fs.rmSync(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
