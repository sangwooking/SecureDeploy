// Actual localhost API + isolated H2. Only transport forwarding; no API mocks.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const origin=process.env.FRONTEND_URL||'http://localhost:5173';
const api='http://127.0.0.1:8085';
(async()=>{
  const http=await request.newContext({baseURL:api});
  const browser=await chromium.launch({headless:true});
  try{
    const createUser=async suffix=>{
      const response=await http.post('/api/auth/signup',{data:{name:'Summary test',email:`summary-${Date.now()}-${suffix}@example.invalid`,password:'Synthetic-local-fixture-813!'}});
      assert.equal(response.status(),200);return response.json();
    };
    const user=await createUser('owner'),other=await createUser('other');
    const zip=execFileSync('python3',['-c',`import io,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('supabase/functions/fixture/index.ts','Deno.serve(async(req)=>{const body=await req.json();return fetch(body.target);});')
sys.stdout.buffer.write(b.getvalue())`]);
    const upload=await http.post('/api/reviews/upload',{headers:{Authorization:`Bearer ${user.accessToken}`},multipart:{
      scanMode:'STANDARD',file:{name:'summary-fixture.zip',mimeType:'application/zip',buffer:zip}}});
    assert.equal(upload.status(),200);const review=await upload.json();
    assert.equal(review.securityScore,100);assert.equal(review.resultSummary.guidance,'REVIEW_NEEDED');
    assert.equal(review.resultSummary.flowCandidates,1);assert.equal(review.resultSummary.coverageStatus,'PARTIAL');
    const saved=await http.get(`/api/reviews/${review.reviewId}`,{headers:{Authorization:`Bearer ${user.accessToken}`}});
    assert.equal(saved.status(),200);assert.deepEqual((await saved.json()).resultSummary,review.resultSummary);
    const denied=await http.get(`/api/reviews/${review.reviewId}`,{headers:{Authorization:`Bearer ${other.accessToken}`}});
    assert.equal(denied.status(),403);
    for(const width of [1440,390,320]){
      const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],blocked=[];
      page.on('pageerror',e=>errors.push(e.message));
      await page.addInitScript(auth=>{
        localStorage.setItem('securedeploy.accessToken',auth.accessToken);
        localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));
      },user);
      await page.route('**/*',route=>{
        const url=new URL(route.request().url());
        if(url.pathname.startsWith('/api/'))return route.continue({url:api+url.pathname+url.search});
        if(url.origin===new URL(origin).origin)return route.continue();
        blocked.push(url.origin);return route.abort();
      });
      await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);
      await page.getByLabel('분석 결과 통합 안내').waitFor();
      const text=await page.locator('#result-content').innerText();
      for(const value of ['100 / 100','보안 근거와 추가 확인 사항','코드 흐름 검토 후보','일부만 확인','전체 안전 점수가 아닙니다'])assert.ok(text.includes(value),value);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
      assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
      await page.screenshot({path:`/private/tmp/securedeploy-risk-summary-live-${width}.png`,fullPage:true});
      await page.close();
    }
    console.log(JSON.stringify({passed:true,database:'ISOLATED_H2',actualZipApi:true,savedSummaryEqual:true,otherUserStatus:403,widths:[1440,390,320],externalCalls:0}));
  }finally{await browser.close();await http.dispose();}
})().catch(e=>{console.error(e);process.exitCode=1;});
