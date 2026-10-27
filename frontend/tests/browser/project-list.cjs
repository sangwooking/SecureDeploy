// Synthetic API responses only; never contacts a backend or external service.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fixture=require('../result-fixture.cjs'),workspaceFixture=require('./workspace-fixture.cjs');
const origin=process.env.FRONTEND_URL||'http://localhost:5173',baseline=process.env.CAPTURE_BASELINE==='1';
(async()=>{const browser=await chromium.launch();try{for(const width of [1440,1280,768,390,320]){
 const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],outbound=[];
 const result=fixture();result.projectName='보안 점검 서비스';
 const data=workspaceFixture('/api/workspace',result),base=data.projects[0];
 base.latestReview.riskSummary.prioritySummary={BLOCKING:2,REVIEW_REQUIRED:7,SHOULD_FIX:13,INFORMATIONAL:0};
 data.projects=[base,{...base,projectId:8,name:'분석 대기 프로젝트',latestReview:null,latestProgress:null},
  {...base,projectId:9,name:'아주긴프로젝트이름으로파일경로나서비스이름이길어져도화면밖으로넘치지않는지확인하는테스트',latestReview:{...base.latestReview,riskSummary:null}}];data.projectCount=3;
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 await page.addInitScript(()=>{localStorage.setItem('securedeploy.accessToken','synthetic-list-only');localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Fixture',email:'list@example.invalid'}));});
 await page.route('**/*',r=>{const u=new URL(r.request().url()),p=u.pathname;if(!p.startsWith('/api/')){if(u.origin===origin)return r.continue();outbound.push(u.origin);return r.abort();}
  const body=p==='/api/workspace'?data:p==='/api/reviews/upload-policy'?require('../upload-policy-fixture.cjs'):p===`/api/reviews/${result.reviewId}`?result:workspaceFixture(p,result);
  return r.fulfill({status:body?200:404,contentType:'application/json',body:JSON.stringify(body||{})});});
 await page.goto(origin+'/#/projects');await page.getByRole('heading',{name:'내 프로젝트 (3)',exact:true}).waitFor();
 const rows=page.locator('.workspace-project-row');assert.equal(await rows.count(),3);
 if(!baseline){
  assert.equal(await page.getByRole('link',{name:'프로젝트 열기',exact:true}).count(),0);
  assert.deepEqual(await rows.first().locator('dd').allTextContents(),['2','7','13']);
  for(const i of [1,2])assert.deepEqual(await rows.nth(i).locator('dd').allTextContents(),['미평가','미평가','미평가']);
  assert.deepEqual(await rows.first().locator('dt').allTextContents(),['반드시 처리','배포 전 확인','수정 권장']);
  for(const row of await rows.all()){assert.equal(await row.locator('a:visible').count(),1);assert.equal(await row.locator('summary').count(),1);assert.equal(await row.locator('p').count(),0);}
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 }
 await page.screenshot({path:`/private/tmp/securedeploy-project-list-${baseline?'before':'after'}-${width}.png`,fullPage:true});
 const link=rows.first().getByRole('link',{name:result.projectName,exact:true});await link.focus();await page.keyboard.press('Enter');
 await page.getByRole('navigation',{name:'프로젝트 메뉴'}).waitFor();assert.ok(page.url().includes('/projects/7/overview'));
 await page.getByRole('navigation',{name:'프로젝트 메뉴'}).getByRole('link',{name:'발견된 문제',exact:true}).click();await page.getByRole('navigation',{name:'분석 결과 메뉴'}).waitFor();
 assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);await page.close();
}console.log(JSON.stringify({passed:true,baseline,widths:[1440,1280,768,390,320],transport:'MOCK_ONLY',nameLinkKeyboardNavigation:true}));}finally{await browser.close();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
