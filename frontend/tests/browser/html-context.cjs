// Synthetic API only. No target HTML execution, backend call or paid AI request.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fixture=require('../result-fixture.cjs');
const workspace=require('./workspace-fixture.cjs');
const url=process.env.FRONTEND_URL||'http://localhost:5173';
(async()=>{
  const browser=await chromium.launch({headless:true});
  try {
    for(const width of [1440,390,320]) {
      const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],blocked=[];
      const result=fixture(),v=result.vulnerabilities[0];
      Object.assign(v,{ruleId:'REACT_DANGEROUS_HTML',category:'CLIENT_XSS',filePath:'src/Notice.tsx',line:21,
        message:'HTML sink',recommendation:'먼저 출력값의 출처를 확인하세요.',
        analysisNote:'HTML_CONTEXT=UNRESOLVED_HTML; SINK_LINE=21; VALUE_LINE=22 · <img src=x onerror=alert(1)>',
        confidence:'HIGH',falsePositiveRisk:'LOW'});
      page.on('pageerror',e=>errors.push(e.message));
      await page.addInitScript(()=>{
        localStorage.setItem('securedeploy.accessToken','synthetic-html-ui-not-a-real-token');
        localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Test',email:'test@example.invalid'}));
      });
      await page.route('**/*',route=>{
        const target=new URL(route.request().url());
        if(!target.pathname.startsWith('/api/')) {
          if(target.origin===new URL(url).origin)return route.continue();
          blocked.push(target.origin);return route.abort();
        }
        const data=target.pathname==='/api/reviews/101'?result:workspace(target.pathname,result);
        return route.fulfill({status:data?200:404,contentType:'application/json',body:JSON.stringify(data??{})});
      });
      await page.goto(`${url}/#/projects/7/findings`);
      await page.getByRole('navigation',{name:'분석 결과 메뉴'}).getByRole('button',{name:'반드시 처리',exact:true}).click();
      const card=page.locator('.action-finding').first();
      await card.waitFor({state:'visible'});
      assert.ok((await card.innerText()).includes('HTML의 출처'));
      await card.locator(':scope > .technical-details > summary').click();
      const text=await card.innerText();
      for(const phrase of ['HTML_CONTEXT=UNRESOLVED_HTML','src/Notice.tsx','HIGH','LOW'])assert.ok(text.includes(phrase),phrase);
      assert.equal(await card.locator('img').count(),0);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
      assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
      console.log(JSON.stringify({width,passed:true,externalRequests:blocked.length}));
      await page.close();
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
