// Explicit opt-in real-model evaluation; no automatic retries. Package updates remain manual Workspace changes.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{execFileSync}=require('node:child_process');
const {stage,pane,resultView}=require('./editor-navigation.cjs');
const root=process.env.SECUREDEPLOY_AI02_INPUT,live=process.env.SECUREDEPLOY_AI03_LIVE==='1',origin='http://127.0.0.1:5189',api='http://127.0.0.1:58043';
if(!root)throw Error('PINNED_INPUT_REQUIRED');const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
(async()=>{const browser=await chromium.launch(),http=await request.newContext({baseURL:api}),results=[];
try{
 const login=async email=>{const r=await http.post('/api/auth/login',{data:{email,password:'Synthetic-AI02-135!'}});assert.equal(r.status(),200);return {Authorization:`Bearer ${(await r.json()).accessToken}`};};
 const headers=await login('ai02-owner@example.invalid'),other=await login('ai02-other@example.invalid');
 const get=async url=>{const r=await http.get(url,{headers});assert.equal(r.status(),200);return r.json();};const history=await get('/api/reviews');
 for(const name of live?['runwhen','urisai']:['runwhen']){
  const base=history.find(r=>r.projectName===name&&r.sourceType==='GITHUB'),before=await get(`/api/reviews/${base.reviewId}`),plans=await get(`/api/reviews/${base.reviewId}/dependencies/update-plans`);
  const index=plans.plans.findIndex(p=>p.packageName==='undici'&&p.lockedVersion===(name==='runwhen'?'7.29.1':'8.11.2')&&p.advisoryId==='GHSA-4qv8-2p9j-2685');assert.ok(index>=0);
  const page=await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true}),errors=[],outbound=[],requests=[];let workspace;
  page.setDefaultTimeout(90000);page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(r.url().endsWith('/generate'))requests.push(r.url());});
  await page.route('**/*',async rt=>{const u=new URL(rt.request().url());if(u.pathname.startsWith('/api/')){const r=await rt.fetch({url:api+u.pathname+u.search,headers:{...rt.request().headers(),origin:'http://localhost:5173'}});return rt.fulfill({response:r,headers:{...r.headers(),'access-control-allow-origin':origin}});}if(u.origin===origin)return rt.continue();outbound.push(u.origin);return rt.abort();});
  try{
   await page.goto(origin);await page.getByPlaceholder('user@test.com').fill('ai02-owner@example.invalid');await page.getByPlaceholder('비밀번호',{exact:true}).fill('Synthetic-AI02-135!');await page.locator('.auth-submit').click();await page.getByRole('navigation',{name:'앱 메뉴'}).waitFor();await page.goto(`${origin}/#/projects/${base.projectId}/findings?review=${base.reviewId}&view=LIBRARIES`);
   await page.getByRole('button',{name:'근거 기반 업데이트 계획 보기',exact:true}).click();const panel=page.getByLabel('AI 의존성 수정 방향',{exact:true});await panel.getByLabel('AI 수정 방향을 요청할 공지').selectOption(String(index));await panel.getByRole('button',{name:'AI 전송 범위 확인',exact:true}).click();await panel.getByText('전송 동의 대기',{exact:true}).waitFor();
   const preview=JSON.parse(await panel.locator('pre').innerText());assert.equal(preview.packageName,'undici');assert.equal(Object.keys(preview).length,8);assert.ok(!JSON.stringify(preview).includes('package.json'));assert.ok(!JSON.stringify(preview).includes(name));assert.equal(requests.length,0);
   const prepareResponses=await get(`/api/reviews/${base.reviewId}/dependencies/ai-proposals/provider`);assert.equal(prepareResponses.origin,live?'OPENAI':'MOCK');
   const generateButton=panel.getByRole('button',{name:'동의한 근거로 AI 수정 방향 생성',exact:true});assert.ok(await generateButton.isDisabled());
   await panel.getByLabel('이 메타데이터의 외부 전송과 API 비용 발생 가능성에 동의합니다.').check();
   const [generated]=await Promise.all([page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/generate'),{timeout:90000}),generateButton.click()]);assert.equal(generated.status(),200);const advice=await generated.json();
   fs.writeFileSync(path.join(root,name,live?'live-advice.json':'mock-advice.json'),JSON.stringify(advice,null,2));
   const proposalUrl=`/api/reviews/${base.reviewId}/dependencies/ai-proposals/${advice.id}`;
   assert.equal((await http.get(proposalUrl,{headers:other})).status(),404);
   assert.equal((await http.post(proposalUrl+'/generate',{headers,data:{approved:true,evidenceHash:advice.evidenceHash}})).status(),409);
   assert.equal(requests.length,1);assert.equal(advice.reviewStatus,'REVIEW_REQUIRED');assert.equal(advice.compatibility,'NOT_VERIFIED');assert.equal(advice.patchApplicable,false);assert.deepEqual(await get(`/api/reviews/${base.reviewId}`),before);
   console.log(JSON.stringify({project:name,mode:live?'LIVE':'MOCK',state:advice.state}));
   if(advice.state!=='GENERATED'){
    results.push({project:name,state:advice.state,modelQuality:'NOT_VERIFIED',applied:false});
    if(advice.state==='FAILED')break; // Provider failure is not automatically retried against another project.
    continue;
   }
   assert.ok(plans.plans[index].sameMajorCandidates.includes(advice.output.candidateVersion));await panel.getByText('응답 검증 통과 · 수정 미적용',{exact:true}).waitFor();await panel.screenshot({path:path.join(root,name,live?'AI_ADVICE.png':'MOCK_ADVICE.png')});
   if(!live){assert.ok((await panel.innerText()).includes('Mock 생성 의견'));results.push({project:name,state:advice.state,provider:'MOCK',applied:false});continue;}
   // A separate package-manager process generates files AFTER the validated AI selection. No project scripts run.
   execFileSync('python3',[path.resolve('scripts/evaluation/prepare_ai03_update.py'),root,name],{encoding:'utf8',timeout:180000,env:{PATH:'/opt/homebrew/bin:/usr/bin:/bin',LANG:'en_US.UTF-8'}});
   await page.getByRole('button',{name:'수정 작업 공간 열기',exact:true}).click();const acquire=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith(`/github/${base.reviewId}`));await page.getByRole('button',{name:'원본 확보 시도 후 새 작업 시작'}).click();workspace=await(await acquire).json();await page.getByRole('navigation',{name:'수정 단계',exact:true}).waitFor();
   for(const filename of ['package.json','package-lock.json']){
    await pane(page,'파일');await page.getByRole('button',{name:filename,exact:true}).click();await pane(page,'코드');const file=workspace.files.find(f=>f.path===filename);const content=await get(`/api/editing-workspaces/${workspace.id}/files/${file.id}`);assert.equal(content.originalHash,sha(fs.readFileSync(path.join(root,name,'before',filename))));
    await page.locator('#source-code').fill(fs.readFileSync(path.join(root,name,'after',filename),'utf8'));const [saved]=await Promise.all([page.waitForResponse(r=>r.request().method()==='PUT'&&r.url().includes(`/files/${file.id}`)),page.getByRole('button',{name:'변경 저장',exact:true}).click()]);assert.equal(saved.status(),200);workspace=await get(`/api/editing-workspaces/${workspace.id}`);
   }
   await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();await page.locator('.source-export > .source-export-approval input').waitFor();const artifacts={};
   for(const format of ['zip','patch']){await page.locator('.source-export > .source-export-approval input').check();const [d]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:format==='zip'?'수정본 ZIP 다운로드':'Patch 다운로드',exact:true}).click()]);artifacts[format]=path.join(root,name,`approved.${format}`);await d.saveAs(artifacts[format]);}
   await stage(page,'재검사 · 비교');const scan=page.getByLabel('수정본 보안 재검사',{exact:true});await scan.getByRole('checkbox').check();await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).waitFor({timeout:60000});const href=await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).getAttribute('href'),after=await get(`/api/reviews/${new URLSearchParams(href.split('?')[1]).get('review')}`);
   assert.equal(before.sca.status,'COMPLETE');assert.equal(after.sca.status,'COMPLETE');assert.equal(after.securityScore,before.securityScore);assert.equal(after.coverage.status,before.coverage.status);assert.deepEqual(after.vulnerabilities.map(v=>[v.ruleId,v.filePath,v.line]),before.vulnerabilities.map(v=>[v.ruleId,v.filePath,v.line]));
   const targeted=d=>d.packageName==='undici'&&d.installedVersion===advice.output.lockedVersion;const old=before.sca.dependencyVulnerabilities.filter(targeted);assert.ok(old.length);assert.equal(after.sca.dependencyVulnerabilities.filter(targeted).length,0);
   for(const f of after.workspaceScan.files)if(f.changed)assert.equal(f.changeOrigin,'MANUAL'); // Model selected a version; it did not generate lockfile bytes.
   const files=JSON.parse(execFileSync('python3',['-c',"import sys,zipfile,json,hashlib\nwith zipfile.ZipFile(sys.argv[1]) as z: print(json.dumps([dict(path=i.filename,mode=i.external_attr>>16,hash=hashlib.sha256(z.read(i)).hexdigest()) for i in z.infolist()]))",artifacts.zip],{encoding:'utf8'}));for(const f of after.workspaceScan.files)assert.equal(files.find(x=>x.path===f.path).hash,f.currentHash);assert.equal(sha(files.sort((a,b)=>a.path<b.path?-1:1).map(f=>`${f.path}\0false\0${f.mode}\0${f.hash}\n`).join('')),after.workspaceScan.inputHash);
   const check=path.join(root,name,'patch-check');fs.cpSync(path.join(root,name,'before'),check,{recursive:true});execFileSync('git',['apply','--check',artifacts.patch],{cwd:check});execFileSync('git',['apply',artifacts.patch],{cwd:check});for(const f of after.workspaceScan.files)assert.equal(sha(fs.readFileSync(path.join(check,f.path))),f.currentHash);
   assert.deepEqual(await get(`/api/reviews/${base.reviewId}`),before);assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);fs.writeFileSync(path.join(root,name,'before-review.json'),JSON.stringify(before,null,2));fs.writeFileSync(path.join(root,name,'after-review.json'),JSON.stringify(after,null,2));
   await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();await page.locator('.source-export > .source-export-approval input').waitFor();await page.screenshot({path:path.join(root,name,'DIFF.png'),fullPage:true});await stage(page,'재검사 · 비교');await page.screenshot({path:path.join(root,name,'AFTER.png'),fullPage:true});
   results.push({project:name,state:advice.state,sourceSha:before.sourceMetadata.commitSha,advisory:advice.output.advisoryId,lockedVersion:advice.output.lockedVersion,modelSelectedVersion:advice.output.candidateVersion,beforeItems:before.sca.dependencyVulnerabilities.length,afterItems:after.sca.dependencyVulnerabilities.length,targetedItemsBefore:old.length,targetedItemsAfter:0,origin:'LIVE_MODEL_DIRECTION_NPM_BYTES_MANUAL_APPROVAL',compatibility:'NOT_VERIFIED',allHashesVerified:true,originalPreserved:true});
  }catch(e){await page.screenshot({path:path.join(root,name,live?'LIVE_FAILURE.png':'MOCK_FAILURE.png'),fullPage:true});throw e;}finally{if(workspace)await http.delete(`/api/editing-workspaces/${workspace.id}`,{headers});await page.close();}
 }
 fs.writeFileSync(path.join(root,live?'live-results.json':'mock-results.json'),JSON.stringify({live,results},null,2));console.log(JSON.stringify({live,results}));
}finally{await browser.close();await http.dispose();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
