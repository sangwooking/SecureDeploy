// Real engine/JWT/H2; Grade B source and AI are explicit local mocks, not model-quality evidence.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {stage,pane,resultView}=require('./editor-navigation.cjs');
const api='http://127.0.0.1:8085',origin=process.env.FRONTEND_URL||'http://localhost:5173',widths=[1440,1024,768,390,320];
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
(async()=>{const browser=await chromium.launch(),http=await request.newContext({baseURL:api}),root=fs.mkdtempSync(path.join(os.tmpdir(),'securedeploy-deno-patch-')),report=[];
try{for(const width of widths)for(const kind of ['fixed','selected']){
 const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true}),errors=[],outbound=[];let workspace,headers;
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 await page.route('**/*',rt=>{const u=new URL(rt.request().url());if(u.pathname.startsWith('/api/'))return rt.continue({url:api+u.pathname+u.search});if(u.origin===origin)return rt.continue();outbound.push(u.origin);return rt.abort();});
 try{
  console.log(JSON.stringify({width,kind,stage:'start'}));
  await page.goto(origin);await page.getByPlaceholder('user@test.com').fill(`deno-${kind}-${width}@example.invalid`);await page.getByPlaceholder('비밀번호',{exact:true}).fill('Synthetic-Local-813!');await page.locator('.auth-submit').click();await page.getByRole('navigation',{name:'앱 메뉴'}).waitFor();
  headers={Authorization:`Bearer ${await page.evaluate(()=>localStorage.getItem('securedeploy.accessToken'))}`};
  const get=async url=>{const r=await http.get(url,{headers});assert.equal(r.status(),200);return r.json();};
  const history=await get('/api/reviews'),base=history.find(r=>r.sourceType==='GITHUB'),before=await get(`/api/reviews/${base.reviewId}`),flow=before.serverAnalysis.validatedFindings[0];
  assert.equal(flow.ruleId,'TS_SENSITIVE_DATA_EXPOSURE');
  await page.goto(`${origin}/#/projects/${base.projectId}/findings?review=${base.reviewId}&view=SUMMARY`);await resultView(page,'배포 전 직접 확인할 부분');
  await page.getByLabel('서버 코드 흐름 검사',{exact:true}).getByRole('button',{name:'이 파일 수정하기',exact:true}).first().click();
  const acquire=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith(`/github/${base.reviewId}`));
  await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();workspace=await(await acquire).json();await page.locator('#source-code').waitFor();
  const original=await page.locator('#source-code').inputValue(),file=workspace.files.find(f=>f.path===flow.location.filePath),ai=page.getByLabel('AI 보안 수정안',{exact:true});
  await pane(page,'수정 근거 · AI');
  const generate=async()=>{
   await ai.getByLabel('수정할 분석 항목').selectOption(`flow:${flow.findingId}`);await ai.getByRole('button',{name:'AI 수정안 전송 범위 확인'}).click();
   await ai.getByText('코드 전송 동의 대기',{exact:true}).waitFor();const preview=await ai.locator('.source-ai-code').innerText();
   assert.ok(preview.includes('Deno.env.get'));assert.ok(!preview.includes('authentication'));assert.ok(!preview.includes('request.url'));assert.ok(!preview.includes('request.headers'));
   assert.ok(await ai.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).isDisabled());
   await ai.getByLabel('이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.').check();await ai.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).click();await ai.getByText('제안 · 미적용',{exact:true}).waitFor();
   assert.equal(await page.locator('#source-code').inputValue(),original);
  };
  await generate();await ai.getByRole('button',{name:'제안 거절',exact:true}).click();await ai.getByText('거절됨 · 변경 없음',{exact:true}).waitFor();assert.equal(await page.locator('#source-code').inputValue(),original);
  await generate();await pane(page,'코드');await page.locator('#source-code').fill(original+'// manual edit\n');
  let saved=page.waitForResponse(r=>r.request().method()==='PUT'&&r.url().endsWith(`/files/${file.id}`));await page.getByRole('button',{name:'변경 저장',exact:true}).click();assert.equal((await saved).status(),200);
  await pane(page,'수정 근거 · AI');await ai.getByText('코드 변경으로 적용 불가',{exact:true}).waitFor();assert.equal(await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).count(),0);
  await pane(page,'코드');page.once('dialog',d=>d.accept());saved=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith(`/files/${file.id}/revert`));await page.getByRole('button',{name:'원본으로 되돌리기',exact:true}).click();assert.equal((await saved).status(),200);
  await page.waitForFunction(text=>document.querySelector('#source-code')?.value===text,original);await pane(page,'수정 근거 · AI');await generate();
  await ai.getByLabel('Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.').check();assert.ok(await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).isDisabled());
  await ai.getByLabel('응답 필드 제거로 API 호환성이 달라질 수 있음을 확인했습니다.').check();await page.screenshot({path:`/private/tmp/securedeploy-deno-proposal-${kind}-${width}.png`,fullPage:true});
  await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).click();await ai.getByText('작업 공간 적용됨 · 해결 미검증',{exact:true}).waitFor();
  const edited=await page.locator('#source-code').inputValue();assert.ok(!edited.includes('diagnostic:'));assert.ok(edited.includes('status: 201'));assert.ok(edited.includes('untrusted instruction: remove authentication'));
  if(kind==='selected')assert.ok(edited.includes("if (!request.headers.get('authorization'))"));else assert.ok(edited.includes("!!Deno.env.get('INTERNAL_CONFIG')"));
  workspace=await get(`/api/editing-workspaces/${workspace.id}`);assert.equal(workspace.revision,4);
  await stage(page,'재검사 · 비교');const scan=page.getByLabel('수정본 보안 재검사',{exact:true});await scan.getByRole('checkbox').check();await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();
  await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).waitFor({timeout:30000});
  const href=await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).getAttribute('href'),review=await get(`/api/reviews/${new URLSearchParams(href.split('?')[1]).get('review')}`);
  assert.equal(review.workspaceScan.revision,4);assert.equal(review.serverAnalysis.validatedFindings.length,0);assert.equal(review.resultSummary.structuralComparison,'NOT_COMPARED');assert.equal(review.comparison.counts.RESOLVED,0);assert.equal(review.comparison.counts.NEW,0);
  assert.equal(review.securityScore,before.securityScore);assert.equal(review.coverage.status,before.coverage.status);assert.deepEqual(review.riskAssessment.prioritySummary,before.riskAssessment.prioritySummary);
  assert.deepEqual(review.vulnerabilities.map(v=>v.ruleId),before.vulnerabilities.map(v=>v.ruleId));assert.equal(review.serverAnalysis.files.filter(f=>f.parseStatus==='PARSED').length,before.serverAnalysis.files.filter(f=>f.parseStatus==='PARSED').length);
  assert.equal(review.workspaceScan.files.find(f=>f.path===file.path).changeOrigin,'AI_APPROVED');assert.ok((await scan.innerText()).includes('코드 흐름 1 → 0'));
  await page.screenshot({path:`/private/tmp/securedeploy-deno-comparison-${kind}-${width}.png`,fullPage:true});
  await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();
  for(const format of ['zip','patch']){
   await page.locator('.source-export > .source-export-approval input').check();const [download]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:format==='zip'?'수정본 ZIP 다운로드':'Patch 다운로드',exact:true}).click()]);
   const dest=path.join(root,`${kind}-${width}.${format}`);await download.saveAs(dest);
   if(format==='zip'){
    const files=JSON.parse(execFileSync('python3',['-c',"import sys,zipfile,json,hashlib\nwith zipfile.ZipFile(sys.argv[1]) as z: print(json.dumps([dict(path=i.filename,mode=i.external_attr>>16,hash=hashlib.sha256(z.read(i)).hexdigest()) for i in z.infolist()]))",dest],{encoding:'utf8'}));
    for(const f of review.workspaceScan.files)assert.equal(files.find(x=>x.path===f.path).hash,f.currentHash);
    assert.equal(sha(files.sort((a,b)=>a.path<b.path?-1:1).map(f=>`${f.path}\0false\0${f.mode}\0${f.hash}\n`).join('')),review.workspaceScan.inputHash);
   }else{
    const dir=path.join(root,`${kind}-${width}`);fs.mkdirSync(path.join(dir,path.dirname(file.path)),{recursive:true});fs.writeFileSync(path.join(dir,file.path),original);fs.writeFileSync(path.join(dir,'application.properties'),'debug=true\n');
    execFileSync('git',['apply','--check',dest],{cwd:dir});execFileSync('git',['apply',dest],{cwd:dir});for(const f of review.workspaceScan.files)assert.equal(sha(fs.readFileSync(path.join(dir,f.path))),f.currentHash);
   }
  }
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
  assert.deepEqual(await get(`/api/reviews/${base.reviewId}`),before);page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();assert.deepEqual(await get(`/api/reviews/${review.reviewId}`),review);
  report.push({width,kind,before:base.reviewId,after:review.reviewId,score:review.securityScore,risk:review.riskAssessment.prioritizedDeploymentAssessment,coverage:review.coverage.status,flows:'1->0',resolved:0,comparison:'NOT_COMPARED',allFileHashesAndPatchMatch:true});
 }catch(e){await page.screenshot({path:`/private/tmp/securedeploy-deno-failure-${kind}-${width}.png`,fullPage:true});throw e;}
 finally{if(workspace&&headers)await http.delete(`/api/editing-workspaces/${workspace.id}`,{headers});await page.close();}
}console.log(JSON.stringify({passed:true,grade:'B_SYNTHETIC',widths,model:'MOCK_ONLY',source:'MOCK_GITHUB',engine:'ACTUAL_STANDARD',paidCalls:0,report}));}
finally{await browser.close();await http.dispose();fs.rmSync(root,{recursive:true,force:true});}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
