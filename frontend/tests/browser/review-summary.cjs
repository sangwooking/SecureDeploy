const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const workspace=require('./workspace-fixture.cjs');
const scenarios=require('../summary-fixture.cjs')();
const origin=process.env.FRONTEND_URL||'http://localhost:5173';
(async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    for(const width of [1440,1024,768,390,320])for(const scenario of scenarios){
      const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],blocked=[];
      page.on('pageerror',e=>errors.push(e.message));
      await page.addInitScript(()=>{
        localStorage.setItem('securedeploy.accessToken','summary-browser-synthetic-token');
        localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Test',email:'test@example.invalid'}));
      });
      await page.route('**/*',route=>{
        const target=new URL(route.request().url());
        if(!target.pathname.startsWith('/api/')){
          if(target.origin===new URL(origin).origin)return route.continue();
          blocked.push(target.origin);return route.abort();
        }
        const data=target.pathname==='/api/reviews/101'?scenario.result:workspace(target.pathname,scenario.result);
        return route.fulfill({status:data?200:404,contentType:'application/json',body:JSON.stringify(data??{})});
      });
      await page.goto(`${origin}/#/projects/7/findings`);
      const labels={SUMMARY:'결과 요약',REVIEW_REQUIRED:'배포 전 직접 확인할 부분',PROGRESS:'변화 보기'};
      await require('./editor-navigation.cjs').resultView(page,labels[scenario.view]);
      await page.locator('#result-content').waitFor();
      if(scenario.id==='html-confidence')await page.locator('.action-finding > .technical-details > summary').first().click();
      await page.waitForFunction(text=>document.querySelector('#result-content')?.innerText.includes(text),scenario.expected[0]);
      for(const text of scenario.expected)assert.ok((await page.locator('#result-content').innerText()).includes(text),`${scenario.id}: ${text}`);
      assert.equal(await page.locator('#result-content img').count(),0);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`${scenario.id}: overflow`);
      assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
      if(scenario.id==='perfect-partial-flow')await page.screenshot({path:`/private/tmp/securedeploy-risk-summary-${width}.png`,fullPage:true});
      await page.close();
    }
    console.log(JSON.stringify({passed:true,scenarios:scenarios.length,widths:[1440,1024,768,390,320],api:'MOCK_ONLY',externalCalls:0}));
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
