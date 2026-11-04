const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const fixture=require('../result-fixture.cjs');
const workspaceFixture=require('./workspace-fixture.cjs');
const root=path.resolve(__dirname,'../../dist-preview');
const url='http://workspace-fixture.local';

(async()=>{
 const browser=await chromium.launch();
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  page.setDefaultTimeout(8000);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const result=fixture(),[code]=result.vulnerabilities;
  const paths=[code.filePath,'package-lock.json','clean.ts','unknown-'+ 'x'.repeat(110)+'.ts'];
  const contents=Array.from({length:16},(_,i)=>'fixture row '+(i+1)).join('\n');
  result.vulnerabilities=[code,code,{...code,vulnerabilityId:52,ruleId:'NO_LINE',line:0}];
  const dependency={...result.sca.dependencyVulnerabilities[0],packageName:'undici',installedVersion:'7.29.1',osvId:'GHSA-2m5v-pch6-74hx',sourceFiles:['package-lock.json','package-lock.json']};
  result.sca.dependencyVulnerabilities=[dependency,dependency];
  result.coverage={status:'PARTIAL',entries:[{kind:'FILE',status:'SELECTED',filePath:'clean.ts'}]};
  const workspace={id:'test-w',reviewId:result.reviewId,revision:1,expiresAt:new Date(Date.now()+3600000).toISOString(),sourceRevision:'fixture',
   identityStatus:'VERIFIED_ZIP_MANIFEST',sourceVerification:{status:'VERIFIED'},
   changedFileIds:[],files:paths.map((path,i)=>({path,id:'f'+i,editable:true,originalHash:'hash',size:contents.length,changed:false}))};
  const writes=[];
  let includeRescan=false, handoff=false;
  const after={...result,reviewId:102,vulnerabilities:[],sca:{...result.sca,dependencyVulnerabilities:[]},
   coverage:{status:'PARTIAL',entries:[{kind:'FILE',status:'SELECTED',filePath:code.filePath}]},
   workspaceScan:{workspaceId:'test-w',originalReviewId:result.reviewId,revision:2,inputHash:'scan-hash',baselineVerified:true,files:[]}};

  await page.addInitScript(id=>{
   localStorage.setItem('securedeploy.accessToken','fixture');
   localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Fixture',email:'fixture@example.invalid'}));
   sessionStorage.setItem('securedeploy.editing.1.'+id,'test-w');
  },result.reviewId);
  await page.route('**/*',async route=>{
   const request=route.request(),u=new URL(request.url());
   if(u.origin!==url)return route.abort();
   if(!u.pathname.startsWith('/api/')){
    const asset=u.pathname==='/'?'index.html':u.pathname.slice(1);
    return route.fulfill({path:path.join(root,asset)});
   }
   if(request.method()!=='GET')writes.push(u.pathname);
   const json=(body,status=200)=>route.fulfill({json:body,status});
   const mock=workspaceFixture(u.pathname,result);
   if(mock)return json(mock);
   if(u.pathname==='/api/reviews/'+result.reviewId)return json(result);
   if(u.pathname==='/api/reviews/102')return json(after);
   if(u.pathname==='/api/editing-workspaces/scans/test-scan')return json({id:'test-scan',workspaceId:'test-w',revision:2,
    inputHash:'scan-hash',reviewId:102,state:'SUCCEEDED',message:'fixture scan',capturedAt:new Date().toISOString()});
   if(u.pathname==='/api/ui-capabilities')return json({schemaVersion:1,providerAvailable:false,dependencyPlans:false,dependencyAdvice:false,workspaceSemanticReview:false,dependencyFiles:true,npmTreePlans:handoff,npmGeneration:false});
   if(handoff&&u.pathname.endsWith('/dependencies/update-plans'))return json({evidenceHash:'same-evidence',plans:[dependency]});
   if(handoff&&u.pathname.endsWith('/dependencies/ai-proposals/demo-advice'))return json({reviewId:result.reviewId,evidenceHash:'same-evidence',state:'GENERATED',planIndex:0,output:{decision:'PROPOSE_UPDATE',candidateVersion:'7.30.1'}});
   if(handoff&&u.pathname.endsWith('/test-w/npm-tree-plans')){
    assert.deepEqual(request.postDataJSON(),{revision:1,planIndex:0,adviceId:'demo-advice'});
    return json({state:'EXECUTION_CONSENT_REQUIRED',message:'Docker 검증 동의 대기',affectedPaths:[],attempts:[]});
   }
   if(u.pathname==='/api/editing-workspaces/test-w')return json(workspace);
   const file=u.pathname.match(/^\/api\/editing-workspaces\/test-w\/files\/(f\d)$/);
   if(file)return json({fileId:file[1],revision:workspace.revision,originalHash:'hash',currentHash:includeRescan?'edited':'hash',text:contents,newline:'LF',bom:false});
   return json({},404);
  });
  await page.goto(`${url}/#/projects/${result.projectId}/edit?review=${result.reviewId}`);
  const tree=page.getByRole('navigation',{name:'프로젝트 파일'});
  const file=name=>tree.getByRole('button',{name:new RegExp(name)});
  await file('Config.java').waitFor();
  assert.match(await file('Config.java').innerText(),/2$/);
  assert.match(await file('clean.ts').innerText(),/0$/);
  assert.match(await file('unknown-').innerText(),/—$/);
  await tree.getByLabel('표시할 파일').selectOption('issues');
  assert.equal(await file('clean.ts').count(),0);
  await file('Config.java').click();
  const issues=page.getByRole('region',{name:'파일의 문제 목록'});
  await issues.getByRole('button',{name:/HARDCODED_SECRET/}).click();
  assert.equal(await page.locator('#source-code').evaluate(el=>el.value.slice(el.selectionStart,el.selectionEnd)),'fixture row 12');
  await issues.getByRole('button',{name:/NO_LINE/}).click();
  assert.ok(!(await issues.getByRole('button',{name:/NO_LINE/}).innerText()).includes('행'));
  await page.reload();
  await issues.getByRole('button',{name:/NO_LINE/,pressed:true}).waitFor();
  await file('package-lock.json').click();
  await issues.getByRole('button',{name:/undici@7.29.1/}).click();
  await page.getByRole('link',{name:'OSV 공지 원문'}).waitFor();
  assert.equal(await issues.getByRole('button').count(),1);
  includeRescan=true;
  workspace.revision=2;
  workspace.changedFileIds=['f0'];
  workspace.files[0].changed=true;
  await page.reload();
  await page.getByText(/수정 후 재검사 전/).first().waitFor();
  await page.evaluate(()=>sessionStorage.setItem('securedeploy.editing.scan.test-w','test-scan'));
  await page.reload();
  await page.getByText(/현재 저장본 재검사/).first().waitFor();
  assert.match(await file('Config.java').innerText(),/0$/);
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  assert.deepEqual(writes,[]);
  handoff=true;includeRescan=false;workspace.revision=1;workspace.changedFileIds=[];workspace.files[0].changed=false;
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(`${url}/#/projects/${result.projectId}/edit?review=${result.reviewId}&advice=demo-advice`);
  await page.reload();
  await page.getByRole('button',{name:'업데이트 수정안 만들기',exact:true}).click();
  await page.getByText('Docker 검증 동의 대기').waitFor();
  assert.deepEqual(writes,['/api/editing-workspaces/test-w/npm-tree-plans']);
  assert.deepEqual(errors,[]);
  console.log('WORKSPACE_FILE_FINDINGS_CHROMIUM_PASS');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
