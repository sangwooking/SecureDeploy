// React presentation only: all API traffic is synthetic, not a live SCA or auth test.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs');
const fixture=require('../result-fixture.cjs'),workspace=require('./workspace-fixture.cjs');
const origin=process.env.FRONTEND_URL||'http://127.0.0.1:5488';
const output=process.env.UI338_OUTPUT||'/private/tmp/securedeploy-ui338';
fs.mkdirSync(output,{recursive:true,mode:0o700});
(async()=>{const browser=await chromium.launch(),checks=[];
try{for(const width of [1440,1280,768,390,320]){
 const page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
 const result=fixture(),dep=result.sca.dependencyVulnerabilities[0];
 result.sca.components.push({ecosystem:dep.ecosystem,packageName:dep.packageName,version:dep.installedVersion,direct:false,
  scope:'devDependencies',sourceFile:'package-lock.json',line:12,versionResolution:'EXACT',context:{environment:'DEVELOPMENT',installedPath:'node_modules/fixture-library',lockLine:12,pathsComplete:false,paths:[],limitations:[]}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{localStorage.setItem('securedeploy.accessToken','synthetic-ui338');localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'검증 사용자',email:'ui338@example.invalid'}));});
 await page.route('**/*',async route=>{const u=new URL(route.request().url());
  if(!u.pathname.startsWith('/api/'))return u.origin===origin?route.continue():route.abort();
  const data=u.pathname==='/api/reviews/upload-policy'?require('../upload-policy-fixture.cjs'):u.pathname===`/api/reviews/${result.reviewId}`?result:workspace(u.pathname,result);
  return route.fulfill({status:data?200:404,contentType:'application/json',body:JSON.stringify(data||{})});
 });
 await page.goto(origin+`/#/projects/${result.projectId}/findings?view=LIBRARIES`);
 await page.getByRole('heading',{name:'외부 라이브러리 보안',exact:true}).waitFor();
 assert.ok((await page.locator('.sca-section').textContent()).includes('다른 라이브러리를 설치하면서 함께 추가된 패키지'));
 assert.ok((await page.locator('.sca-section').textContent()).includes('운영에서 실행되는지는 별도 확인'));
 assert.equal(await page.getByRole('button',{name:'자동 수정안 만들기',exact:true}).count(),0);
 await page.evaluate(()=>window.scrollTo(0,0));
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 await page.screenshot({path:`${output}/after-libraries-${width}.png`,fullPage:true});
 await page.getByRole('button',{name:'결과 요약',exact:true}).click();
 const first=page.locator('.next-actions li').first();await first.waitFor();
 assert.equal(await first.getAttribute('data-priority'),'BLOCKING');
 await page.keyboard.press('Tab');await first.getByRole('button',{name:'수정 방법 확인'}).focus();
 assert.ok(await first.getByRole('button').evaluate(e=>getComputedStyle(e).outlineStyle!=='none'));
 await first.getByRole('button').click();await page.locator('.action-finding').first().waitFor();
 assert.ok(!(await page.locator('.action-finding .finding-origin').first().innerText()).includes('HIGH'));
 assert.deepEqual(errors,[]);checks.push({width,libraryRoute:true,developmentIndirect:true,firstPriorityPreserved:true,keyboardFocus:true,overflow:false});await page.close();
}console.log(JSON.stringify({passed:true,transport:'MOCK_ONLY',checks}));}finally{await browser.close();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
