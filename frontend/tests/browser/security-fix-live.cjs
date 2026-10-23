// Grade B fixtures only: real React/JWT/H2/analysis, mocked source acquisition and AI.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {stage,pane,resultView}=require('./editor-navigation.cjs');
const api='http://127.0.0.1:8085',origin=process.env.FRONTEND_URL||'http://localhost:5173';
const widths=[1440,1024,768,390,320];
const originalProperties='debug=true\nserver.error.include-stacktrace=always\n';
const safeProperties='debug=false\nserver.error.include-stacktrace=never\nserver.servlet.session.cookie.secure=true\n';
const safeDeno="Deno.serve(async request => {\n  return Response.json({status: 'ok'});\n});\n";
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const facts=r=>({reviewId:r.reviewId,score:r.securityScore,risk:r.riskAssessment?.prioritizedDeploymentAssessment,
 coverage:r.coverage?.status,ruleIds:r.vulnerabilities.map(v=>v.ruleId).sort(),
 flows:(r.serverAnalysis?.validatedFindings||[]).map(f=>({ruleId:f.ruleId,source:f.evidence.map(e=>({file:e.source.filePath,line:e.source.line,kind:e.source.kind})),sink:f.location,comparison:f.comparisonPolicy})),
 comparison:r.comparison?.counts,structuralComparison:r.resultSummary?.structuralComparison});
(async()=>{
 const browser=await chromium.launch({headless:true}),http=await request.newContext({baseURL:api});
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'securedeploy-security-fix-')),report=[];
 try{for(const width of widths)for(const kind of ['rule','flow']){
  const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true}),errors=[],outbound=[];
  let workspace,headers;
  page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.route('**/*',rt=>{const u=new URL(rt.request().url());if(u.pathname.startsWith('/api/'))return rt.continue({url:api+u.pathname+u.search});if(u.origin===origin)return rt.continue();outbound.push(u.origin);return rt.abort();});
  try{
   console.log(JSON.stringify({width,kind,stage:'start'}));
   await page.goto(origin);await page.getByPlaceholder('user@test.com').fill(`repair-${kind}-${width}@example.invalid`);
   await page.getByPlaceholder('비밀번호',{exact:true}).fill('Synthetic-Local-813!');await page.locator('.auth-submit').click();
   await page.getByRole('navigation',{name:'앱 메뉴'}).waitFor();
   headers={Authorization:`Bearer ${await page.evaluate(()=>localStorage.getItem('securedeploy.accessToken'))}`};
   const get=async url=>{const response=await http.get(url,{headers});assert.equal(response.status(),200);return response.json();};
   const history=await get('/api/reviews'),base=history.find(r=>r.sourceType==='GITHUB');assert.ok(base);
   const before=await get(`/api/reviews/${base.reviewId}`),observations=[facts(before)];
   await page.goto(`${origin}/#/projects/${base.projectId}/findings?review=${base.reviewId}&view=SUMMARY`);
   await resultView(page,kind==='rule'?'수정 권장':'배포 전 직접 확인할 부분');
   if(kind==='flow')assert.equal(before.serverAnalysis.validatedFindings[0].ruleId,'TS_SENSITIVE_DATA_EXPOSURE');
   await page.getByRole('button',{name:'이 파일 수정하기',exact:true}).first().click();
   const created=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().includes(`/github/${base.reviewId}`));
   await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).click();workspace=await(await created).json();
   await page.locator('#source-code').waitFor();
   const file=workspace.files.find(f=>f.path===(kind==='rule'?'application.properties':'supabase/functions/inspect/index.ts'));assert.ok(file);
   assert.equal(await page.locator('#source-code').inputValue(),kind==='rule'?originalProperties:"Deno.serve(async request => {\n  return Response.json(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n});\n");
   const scan=page.getByLabel('수정본 보안 재검사',{exact:true});
   const rescan=async()=>{
    workspace=await get(`/api/editing-workspaces/${workspace.id}`);
    await stage(page,'재검사 · 비교');await scan.getByRole('checkbox').check();
    const started=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith(`/${workspace.id}/scans`));
    await scan.getByRole('button',{name:'수정본 다시 검사',exact:true}).click();const response=await started;assert.equal(response.status(),202);
    const job=await response.json();let completed;
    for(let i=0;i<300;i++){completed=await get(`/api/editing-workspaces/scans/${job.id}`);if(completed.state!=='RUNNING')break;await page.waitForTimeout(100);}
    assert.equal(completed.state,'SUCCEEDED');
    await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).waitFor({timeout:30000});
    await page.waitForFunction(id=>Array.from(document.querySelectorAll('.workspace-scan a')).some(a=>new URLSearchParams(a.getAttribute('href').split('?')[1]).get('review')===String(id)),completed.reviewId);
    const href=await scan.getByRole('link',{name:'저장된 수정본 결과와 History 열기'}).getAttribute('href');
    const id=new URLSearchParams(href.split('?')[1]).get('review'),saved=await get(`/api/reviews/${id}`);
    assert.equal(saved.workspaceScan.revision,workspace.revision);assert.equal(saved.workspaceScan.originalReviewId,base.reviewId);
    assert.ok((await scan.innerText()).includes('수정본은 새 GitHub commit이 아닙니다'));
    assert.ok(!(await scan.innerText()).includes('현재 commit 정보 없음'));
    assert.equal(saved.sourceType,'WORKSPACE');assert.ok(saved.workspaceScan.baselineVerified);
    observations.push(facts(saved));return saved;
   };
   const edit=async text=>{await stage(page,'코드 편집');await pane(page,'코드');await page.locator('#source-code').fill(text);
    const saved=page.waitForResponse(r=>r.request().method()==='PUT'&&r.url().endsWith(`/files/${file.id}`));
    await page.getByRole('button',{name:'변경 저장',exact:true}).click();assert.equal((await saved).status(),200);
    await page.waitForFunction(()=>document.querySelector('.source-editor-actions .primary-button')?.disabled);
   };
   let saved;
   if(kind==='rule'){
    const unchanged=await rescan();assert.equal(unchanged.comparison.counts.RESOLVED,0);assert.equal(unchanged.comparison.counts.REMAINING,2);
    assert.equal(unchanged.securityScore,before.securityScore);
    await stage(page,'코드 편집');await pane(page,'수정 근거 · AI');const ai=page.getByLabel('보안 수정안',{exact:true});
    const generate=async()=>{
     await ai.getByLabel('수정할 분석 항목').selectOption({label:'DEBUG_ENABLED · 원본 1행'});
     await ai.getByRole('button',{name:'AI 수정안 전송 범위 확인'}).click();assert.ok(await ai.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).isDisabled());
     await ai.getByLabel('이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.').check();
     await ai.getByRole('button',{name:'동의한 코드로 AI 수정안 생성'}).click();await ai.getByText('제안 · 미적용',{exact:true}).waitFor();
     assert.ok((await page.locator('#source-code').inputValue()).startsWith('debug=true'));
    };
    await generate();await ai.getByRole('button',{name:'제안 거절',exact:true}).click();await ai.getByText('거절됨 · 변경 없음',{exact:true}).waitFor();
    assert.equal(await page.locator('#source-code').inputValue(),originalProperties);
    await generate();const proposals=await get(`/api/editing-workspaces/${workspace.id}/patches`),proposal=proposals.find(p=>p.state==='PROPOSED');assert.ok(proposal);
    await edit(originalProperties+'# source changed after proposal\n');await pane(page,'수정 근거 · AI');
    await ai.getByText('코드 변경으로 적용 불가',{exact:true}).waitFor();assert.equal(await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).count(),0);
    const stale=await http.post(`/api/editing-workspaces/${workspace.id}/patches/${proposal.id}/apply`,{headers,data:{revision:proposal.revision,currentHash:proposal.currentHash,approved:true}});assert.equal(stale.status(),409);
    await generate();assert.ok(await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).isDisabled());
    await ai.getByLabel('Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.').check();await ai.getByRole('button',{name:'검토한 AI 수정안 적용'}).click();
    await page.waitForFunction(()=>document.querySelector('#source-code')?.value.startsWith('debug=false'));
    const approved=await rescan();assert.ok(approved.comparison.findings.some(f=>f.status==='RESOLVED'&&f.before?.risk.ruleId==='DEBUG_ENABLED'));
    assert.equal(approved.workspaceScan.files.find(f=>f.path===file.path).changeOrigin,'AI_APPROVED');assert.ok(approved.securityScore>before.securityScore);
    await edit('debug=false\nserver.error.include-stacktrace=always\nserver.servlet.session.cookie.secure=false\n');
    const added=await rescan();assert.ok(added.comparison.counts.NEW>0);assert.ok(added.comparison.counts.REMAINING>0);assert.ok(added.comparison.counts.RESOLVED>0);
    await edit(safeProperties);saved=await rescan();assert.equal(saved.vulnerabilities.length,0);assert.equal(saved.comparison.counts.RESOLVED,2);
    await scan.getByRole('button',{name:/해결된 문제/}).click();await scan.getByText('비교 가능한 현재 분석에서 기존 문제가 더 이상 확인되지 않았습니다. 완전한 안전을 보장하지 않습니다.',{exact:true}).first().waitFor();
   }else{
    await edit(safeDeno);saved=await rescan();assert.equal(saved.serverAnalysis.validatedFindings.length,0);
    assert.equal(saved.comparison.counts.RESOLVED,0);assert.equal(saved.resultSummary.structuralComparison,'NOT_COMPARED');
    assert.equal(saved.securityScore,before.securityScore);assert.deepEqual(saved.riskAssessment.prioritySummary,before.riskAssessment.prioritySummary);
    assert.ok((await scan.innerText()).includes('코드 흐름 1 → 0'));assert.ok((await scan.innerText()).includes('NOT_COMPARED'));
   }
   await page.screenshot({path:`/private/tmp/securedeploy-fix-${kind}-comparison-${width}.png`,fullPage:true});
   await stage(page,'변경 검토 · 다운로드');await page.getByRole('button',{name:'전체 변경 Diff 확인'}).click();await page.locator('.source-export-approval input').check();
   for(const format of ['zip','patch']){
    await page.locator('.source-export-approval input').check();
    console.log(JSON.stringify({width,kind,stage:'export',format}));
    const [download]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:format==='zip'?'수정본 ZIP 다운로드':'Patch 다운로드',exact:true}).click()]);
    const dest=path.join(temp,`${kind}-${width}.${format}`);await download.saveAs(dest);
    if(format==='zip'){
     const archive=JSON.parse(execFileSync('python3',['-c',"import sys,zipfile,json,hashlib\nwith zipfile.ZipFile(sys.argv[1]) as z: print(json.dumps([dict(path=i.filename.rstrip('/'),directory=i.is_dir(),mode=i.external_attr>>16,hash=hashlib.sha256(z.read(i)).hexdigest()) for i in z.infolist()]))",dest],{encoding:'utf8'}));
     const files=Object.fromEntries(archive.filter(f=>!f.directory).map(f=>[f.path,f.hash]));
     const manifest=archive.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0).map(f=>`${f.path}\0${f.directory}\0${f.mode}\0${f.hash}\n`).join('');
     assert.equal(sha(manifest),saved.workspaceScan.inputHash);
     for(const f of saved.workspaceScan.files)assert.equal(files[f.path],f.currentHash,f.path);
     assert.equal(Object.keys(files).length,saved.workspaceScan.files.length);assert.equal(files[file.path],sha(kind==='rule'?safeProperties:safeDeno));
    }else{
     const root=path.join(temp,`${kind}-${width}-apply`);fs.mkdirSync(root);
     const originals=kind==='rule'?{'application.properties':originalProperties,'src/example.ts':"export const value = 'original';\n",'assets/example.bin':Buffer.from([0,255,2])}
      :{[file.path]:"Deno.serve(async request => {\n  return Response.json(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n});\n"};
     for(const [name,bytes]of Object.entries(originals)){const target=path.join(root,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,bytes);}
     execFileSync('git',['apply','--check',dest],{cwd:root});execFileSync('git',['apply',dest],{cwd:root});
     for(const f of saved.workspaceScan.files)assert.equal(sha(fs.readFileSync(path.join(root,f.path))),f.currentHash);
    }
   }
   await page.screenshot({path:`/private/tmp/securedeploy-fix-${kind}-diff-${width}.png`,fullPage:true});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
   page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'작업 공간 삭제',exact:true}).click();await page.getByRole('button',{name:'원본 확보 후 작업 공간 시작'}).waitFor();
   assert.deepEqual(await get(`/api/reviews/${base.reviewId}`),before);assert.deepEqual(await get(`/api/reviews/${saved.reviewId}`),saved);
   await page.goto(`${origin}/#/projects/${base.projectId}/history`);await page.getByText(`분석 #${saved.reviewId}`,{exact:false}).waitFor();
   report.push({width,kind,observations,zipAllFileHashesMatch:true,patchDownloaded:true,originalUnchanged:true,historyPersists:true});
  }catch(e){await page.screenshot({path:`/private/tmp/securedeploy-fix-failed-${kind}-${width}.png`,fullPage:true});throw e;}
  finally{if(workspace&&headers)await http.delete(`/api/editing-workspaces/${workspace.id}`,{headers});await page.close();}
 }
 console.log(JSON.stringify({passed:true,grade:'B_SYNTHETIC',widths,engine:'ACTUAL_STANDARD',database:'ISOLATED_H2',source:'MOCK_GITHUB',ai:'MOCK_ONLY',paidCalls:0,report}));
 }finally{await browser.close();await http.dispose();fs.rmSync(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
